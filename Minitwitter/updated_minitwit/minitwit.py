# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~

    A microblogging application written with Flask and sqlite3.

    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import os
import time
import redis
import cPickle
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
    render_template, abort, g, flash, _app_ctx_stack, json, jsonify
from werkzeug import check_password_hash, generate_password_hash
from flask import Response
from flask_basicauth import BasicAuth
from flask_pymongo import PyMongo
from pymongo import MongoClient
from flask_sessionstore import Session
# from BasicAuth import check_credentials

import requests
from bson.objectid import ObjectId
# configuration
REDIS_URL = os.getenv('REDISTOGO_URL', 'redis://localhost:6379')
DATABASE = 'minitwit'
PER_PAGE = 30
DEBUG = False
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

# create our little application :)
app = Flask('minitwit')

app.config.from_object(__name__)
# app.config.from_envvar('MINITWIT_SETTINGS', silent=True)
app.config['SESSION_TYPE'] = 'redis'
# app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:////tmp/minitwit.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
client = MongoClient('127.0.0.1', 27017)
# db = client[minitwit.db]
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)
app.config['MONGO_DBNAME'] = 'minitwit'
app.config['MONGO_HOST'] = '127.0.0.1'
app.config['MONGO_PORT'] = 27017
mongo = PyMongo(app)

redisClient = redis.from_url(REDIS_URL)


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    # top = _app_ctx_stack.top
    # if not hasattr(top, 'sqlite_db'):
    # top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
    # top.sqlite_db.row_factory = sqlite3.Row
    # return top.sqlite_db
    db = client.minitwit
    return db


class MyBasicAuth(BasicAuth):
    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(app)
        else:
            self.app = None

    def check_credentials(self, username, password):
        if username != None:
            user_key = username
            if redisClient.get(user_key):
                user = cPickle.loads(redisClient.get(user_key))
            else:
                user = get_user_details(username)
                redisClient.set(user_key, cPickle.dumps(user))
                redisClient.expire(user_key, 60)

            if user != None:
                if user[0].get('username') == username:
                    if check_password_hash(user[0].get('pw_hash'), password):
                        return 'true'


basic_auth = MyBasicAuth(app)


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


def populate_db():
    """Populates the database."""
    # db = get_db()
    # with app.open_resource('mongopopulate.js', mode='r') as f:
    #     db.cursor().executescript(f.read())
    # db.commit()
    os.system('sh runMongo.sh')


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')


@app.cli.command('populatedb')
def populatedb_command():
    """Inserts data in  the database tables."""
    populate_db()
    print('Rows inserted in  the database.')


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    # rv = query_db('select user_id from user where username = ?',
    # [username], one=True)
    user_id = mongo.db.users.find_one({'username': username}, {'user_id': 1, '_id': 0})
    return user_id['user_id'] if user_id else None

def get_message_id(message_id):
    """Convenience method to look up the id for a username."""
    # rv = query_db('select user_id from user where username = ?',
    print "message_id", message_id
    msg_obj_id = mongo.db.messages.find({'_id':ObjectId(message_id)})
    return msg_obj_id

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
           (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        # g.user = query_db('select * from user where user_id = ?',
        #                  [session['user_id']], one=True)
        print "Before Request"
        g.user = mongo.db.users.find({"user_id": session['user_id']})


def get_logged_user_timeline():
    followers = mongo.db.users.find({'user_id': session['user_id']}, {'whom_id': 1, '_id': 0})
    # messages= mongo.db.messages.find({$or:[{'author_id': session['user_id']},{'author_id':{$in:followers}}]} , {'author_id':1,'text': 1, '_id':0})
    # users=mongo.db.users.find({$or:[{'user_id': session['user_id']},{'user_id':{$in:followers}}]} , {'user_id': 1, 'username':1,'email': 1,'pw_hash':1,'_id':0})
    messages_list = []
    m = 0

    for row in followers:

        if row != {}:
            whom_id = row['whom_id']
            whom_id.append(session['user_id'])

            for i in whom_id:
                messages = mongo.db.messages.find({'author_id': i},
                                                  {'author_id': 1, 'text': 1, 'pub_date': 1, '_id': 1})
                #print "Inside for-->",list(messages)
                for message in messages:
                    users = mongo.db.users.find({'user_id': message['author_id']},
                                                {'user_id': 1, 'username': 1, 'email': 1, 'pw_hash': 1, '_id': 1})
                    #print "Inside message user-->",list(users)
                    for data in users:
                        messages_list.append(
                            {'user_id': data['user_id'], 'username': data['username'], 'text': message['text'],
                             'pub_date': message['pub_date'], 'email': data['email'], 'message_id':message['_id']})
    print messages_list
    return messages_list


def get_public_timeline():
    messages = mongo.db.messages.find().sort('pub_date', -1)
    return messages


def get_follower(profile_user_id):
    # followed = query_db('''select 1 from follower where
    # follower.who_id = ? and follower.whom_id = ?''',
    # [session['user_id'], profile_user['user_id']],
    # one=True) is not None

    # return followed
    # user_id= session['user_id']
    # profile_user_id = profile_user['user_id']
    # followed = mongo.db.users.find({follows: {$elemMatch:{'who_id': user_id, 'whom_id': profile_user_id}}})

    followed = mongo.db.users.find({'user_id': profile_user_id}, {'whom_id': 1, '_id': 0})
    return followed

def get_user_timeline(profile_user):
    print "In User timeline"
    # user_id= mongo.db.users.find_one({'username': profile_user[0].get('username')}, {'user_id':1, '_id':0})
    user_id = None
    user_key = profile_user[0].get('username')
    if redisClient.get(user_key):
        user_details = cPickle.loads(redisClient.get(user_key))
    else:
        user_details = get_user_details(profile_user[0].get('username'))
        redisClient.set(user_key, cPickle.dumps(user_details))
        redisClient.expire(user_key, 60)

    for row in user_details:
        user_id = row['user_id']
    messages = mongo.db.messages.find({'author_id': user_id},
                                      {'author_id': 1, 'text': 1, 'pub_date': 1, 'email': 1, '_id': 0})

    return messages


def create_user_follower(whom_id):
    # db = get_db()
    # db.execute('insert into follower (who_id, whom_id) values (?, ?)',
    # [session['user_id'], whom_id])
    # db.commit()
    print "Session User", session['user_id']
    mongo.db.users.update({'user_id': session['user_id']}, {'$push': {'whom_id': whom_id}})


def remove_user_follower(whom_id):
    # db = get_db()
    # db.execute('delete from follower where who_id=? and whom_id=?',
    # [session['user_id'], whom_id])
    # db.commit()
    mongo.db.users.update({'user_id': session['user_id']}, {'$pull': {'whom_id': whom_id}})

def liked(message_id):
    print "Session User", repr(message_id)
    tmpId =  repr(message_id)

    mongo.db.messages.update({'_id':tmpId}, {'$push':{'liked_by': session['user_id']}})

def unliked(message_id):
    print "Session User", session['user_id']
    mongo.db.messages.update({'message_id':message_id}, {'$pull':{'liked_by': session_['user_id']}})


def add_post(text):
    # db = get_db()
    # db.execute('''insert into message (author_id, text, pub_date)
    #      values (?, ?, ?)''', (session['user_id'], text,
    #                            int(time.time())))
    # db.commit()
    # if request.form['text']:
    #    print "I am in add_post",request.form['text']

    user = mongo.db.users.find_one(
        {'user_id': session['user_id']}, {'email': 1, 'username': 1})

    mongo.db.messages.insert(
        {'author_id': session['user_id'],
         'email': user['email'],
         'username': user['username'],
         'text': text,
         'pub_date': int(time.time())})


def get_user_details(username):
    user_details = mongo.db.users.find({'username': username},
                                       {'username': 1, 'pw_hash': 1, 'user_id': 1, 'email': 1, '_id': 0})
    user = []
    for record in user_details:
        username = record['username']
        pw_hash = record['pw_hash']
        user_id = record['user_id']
        user.append({'username': username, 'pw_hash': pw_hash, 'user_id': user_id, 'email': record['email']})

    return user if user else None

def leaderboardImplement():
    messages=get_public_timeline()
    cacheValue=redisClient.get('leaderboardKey')
    if cacheValue is None:
        valueSorted=[cPickle.loads(likeVal) for likeVal in redisClient.zrevrange('message_like', 0,-1)]
        redisClient.setex('leaderboardKey',cPickle.dumps(valueSorted),60)
    else:
        valueSorted=cPickle.loads(cacheValue)
    print"valuestored:",valueSorted
    return valueSorted

@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """

    if not g.user:
        print "G.User", g.user
        return redirect(url_for('public_timeline'))
        user_key = logged_user
        if redisClient.get(user_key):
            print "LOgged user messages from redis"
            return render_template('timeline.html', messages=cPickle.loads(redisClient.get(user_key)))
        else:
            messages = get_logged_user_timeline()
            print "Logged user messages from database", messages
            redisClient.set(user_key, cPickle.dumps(messages))
            redisClient.expire(user_key, 30)
        return render_template('timeline.html', messages=messages)
    return render_template('timeline.html', messages=get_logged_user_timeline())


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    key = public_timeline
    message_list = []
    if redisClient.get(key):
        print "Returned from Cache"
        return render_template('timeline.html', messages=cPickle.loads(redisClient.get(key)))
    else:
        user_messages = get_public_timeline()

        for row in user_messages:
            author_id = row['author_id']
            users = mongo.db.users.find_one({'user_id': author_id}, {'user_id': 1, 'username': 1, 'email': 1, '_id': 0})
            message_list.append({'username': users['username'], 'email': users['email'], 'user_id': users['user_id'],
                                 'pub_date': row['pub_date'], 'text': row['text'], 'author_id': row['author_id']})
            redisClient.set(key, cPickle.dumps(message_list))
            redisClient.expire(key, 60)
        return render_template('timeline.html', messages=message_list)


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""

    username_key = username
    if redisClient.get(username_key):
        profile_user = cPickle.loads(redisClient.get(username_key))
    else:
        profile_user = get_user_details(username)
        redisClient.set(username_key, cPickle.dumps(profile_user))
        redisClient.expire(username_key, 60)

    followed = False
    message_list = []
    user_hashkey = str(profile_user[0].get('user_id'))
    if profile_user is None:
        abort(404)

    if g.user:
        print "G user", g.user[0].get('user_id')
        followers = get_follower(g.user[0].get('user_id'))
        whom_id = followers[0].get('whom_id')

        if whom_id != None:
            for i in whom_id:
                i = int(i)
                profile_user_id = int(profile_user[0].get('user_id'))

                if i == profile_user_id:
                    followed = True
                    print "User Followed", profile_user[0].get('user_id')
    if redisClient.get(user_hashkey):
        print "User Timeline returned from Cache"
        return render_template(
            'timeline.html', messages=cPickle.loads(redisClient.get(user_hashkey)), followed=followed,
            profile_user=profile_user)
    else:
        messages = get_user_timeline(profile_user)
        for row in messages:
            message_list.append({'email': row['email'], 'pub_date': row['pub_date'], 'text': row['text']})
        print " User timeline Messages retrieved from database"
        redisClient.set(user_hashkey, cPickle.dumps(message_list))
        redisClient.expire(user_hashkey, 60)

    return render_template(
        'timeline.html', messages=message_list, followed=followed, profile_user=profile_user)

@app.route('/leaderboard/list')
def leaderboard():
    list1=leaderboardImplement()
    message_list=[]
    print"--->",type(list1)
    for data in list1:
        print "Data:", data
        print "Type", type(data)
        messages= mongo.db.messages.find({'_id': ObjectId(str(data))},{'author_id':1,'text':1,'pub_date':1,'email':1,'_id':1})
        for row in messages:
            print "Message tect", row['text']
            message_list.append({'message_id': row['_id'], 'text': row['text'], 'pub_date': row['pub_date'],'email': row['email']})
    return render_template(
        'leader.html', messages=message_list)

@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)

    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    create_user_follower(whom_id)
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))



@app.route('/<id>/like')
def liked_message(id):
    """Adds the current user as liked_by of the given message."""
    #if not g.user:
        #abort(401)
    #msg_obj_id = mongo.db.messages.find_one({'_id':ObjectId(id)})
    redisClient.zincrby('message_like',cPickle.dumps(id))
    return redirect(url_for('timeline',message_id=id))

@app.route('/<message_id>/unlike',methods=['GET', 'POST'])
#@basic_auth.required
def unliked_message(message_id):
    """Adds the current user as liked_by of the given message."""
    if not g.user:
        abort(401)
    print"inside liked msg: ",repr(ObjectId(message_id))

    #message_id = get_message_id(ObjectId(message_id))
    for value in message_id:
        print "Object id from get message Id",value
    if message_id is None:
        abort(404)
    #redisClient.srem(message_id,session['user_id'])
	redisClient.zincrby('message_like',cPickle.dumps(message_id), -1)
	flash('You liked the message with id "%s"' % message_id)
    return redirect(url_for('timeline',message_id=message_id))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    remove_user_follower(whom_id)
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    text = request.form['text']
    user_key = str(session['user_id'])
    if 'user_id' not in session:
        abort(401)

    if text:
        add_post(text)
        if redisClient.get(user_key):
            print "Record Deleted"
            redisClient.delete(user_key)
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user_key = request.form['username']
        if redisClient.get(user_key):
            user = cPickle.loads(redisClient.get(user_key))
        else:
            user = get_user_details(request.form['username'])
            redisClient.set(user_key, cPickle.dumps(user))
            redisClient.expire(user_key, 60)

        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user[0].get('pw_hash'),
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user[0].get('user_id')
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            # db = get_db()
            # db.execute('''insert into user (
            # username, email, pw_hash) values (?, ?, ?)''',
            # [request.form['username'], request.form['email'],
            # generate_password_hash(request.form['password'])])
            # db.commit()
            ids = mongo.db.users.find({}, {"user_id": 1, "_id": 0}).sort("user_id", -1)
            latest_user_id = ids[0].get('user_id')
            latest_user_id += 1
            mongo.db.users.insert(
                {'user_id': latest_user_id,
                 'username': request.form['username'],
                 'email': request.form['email'],
                 'pw_hash': generate_password_hash(request.form['password']),
                 })

            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


"""Code to add new API"""


@app.route('/api/statuses/home_timeline')
@basic_auth.required
def home_timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    user_key = str(session['user_id'])

    if not g.user:
        error_code = 404
        redirect_url = '/api/statuses/public_timeline'
        return jsonify(error_code=error_code, redirect_url=redirect_url)

    if redisClient.get(user_key):
        print "Logged user messages from redis"
        status_code = 200
        return jsonify(user_message=cPickle.loads(redisClient.get(user_key)), status_code=status_code)

    else:
        messages = get_logged_user_timeline()
        user_data_list = []
        for row in messages:
            user_data_list.append(
                {'user': row['user_id'], 'message': row['text'], 'pub_date': format_datetime(row['pub_date'])})
        status_code = 200
        print "Logged user messages from database"
        redisClient.set(user_key, cPickle.dumps(user_data_list))
        redisClient.expire(user_key, 30)

    return jsonify(user_message=user_data_list, status_code=status_code)


@app.route('/api/statuses/public_timeline')
@basic_auth.required
def general_timeline():
    messages = get_public_timeline()

    users_data_list = []

    for row in messages:
        user_id = row['author_id']
        message = row['text']
        users_data_list.append({'user': user_id, 'message': message})
    status_code = 200
    return jsonify(users_messages=users_data_list, status_code=status_code)


@app.route('/api/statuses/user_timeline/<username>')
@basic_auth.required
def users_timeline(username):
    """Display's a users tweets."""
    # username= request.args['username']
    username_key = username
    if redisClient.get(username_key):
        profile_user = cPickle.loads(redisClient.get(username_key))
    else:
        profile_user = get_user_details(username)
        redisClient.set(username_key, cPickle.dumps(profile_user))
        redisClient.expire(username_key, 60)
    message_list = []
    user_key = str(profile_user[0].get('user_id'))

    if profile_user is None:
        abort(404)
    followed = False

    if g.user:
        followed = get_follower(profile_user)
    if redisClient.get(user_key):
        print "User timeline read from Cache in API"
        status_code = 200
        return jsonify(status_code=status_code, user_messages_json=cPickle.loads(redisClient.get(user_key)),
                       profile_user=profile_user[0].get('user_id'))
    else:
        user_messages = get_user_timeline(profile_user)
        user_messages_list = []
        profile_user_list = []

        for row in user_messages:
            text = row['text']
            pub_date = row['pub_date']
            author_id = row['author_id']
            # user_messages_list.append({'user': row[5], 'message': row[2], 'pub_date': datetime.fromtimestamp(int(row[3])).strftime('%Y-%m-%d %H:%M')})
            user_messages_list.append({'user': author_id, 'message': text,
                                       'pub_date': datetime.fromtimestamp(int(pub_date)).strftime('%Y-%m-%d %H:%M')})
        print "The recotds are retrieved from database API"
        redisClient.set(user_key, cPickle.dumps(user_messages_list))
        redisClient.expire(user_key, 60)

        # followed_list=[]
        # for data in followed:
        #     print "Data", data
        #     followed_list.append({'whom_id':data['whom_id']})
        status_code = 200
    return jsonify(status_code=status_code, user_messages_json=user_messages_list,
                   profile_user=profile_user[0].get('user_id'))


#####
@app.route('/api/friendships/create', methods=['GET', 'POST'])
@basic_auth.required
def create_follower():
    """Adds the current user as follower of the given user."""

    username = request.args.get('username')

    error_code = 200

    if not g.user:
        error_code = 401

    whom_id = get_user_id(username)

    if whom_id is None:
        error_code = 404
    create_user_follower(whom_id)

    message_on_screen = 'You are now following:', username
    return jsonify(username=username, error_code=error_code, message_on_screen=message_on_screen)


@app.route('/api/friendships/<username>', methods=['GET', 'DELETE'])
@basic_auth.required
def remove_follower(username):
    """Removes the current user as follower of the given user."""
    # username=request.args.get('username')

    if not g.user:
        error_code = 401
        message_on_screen = 'You are not authorized to do this operation'
        return jsonify(error_code=error_code, error_message=message_on_screen)

    whom_id = get_user_id(username)
    if whom_id is None:
        error_code = 404
        message_on_screen = 'Follower not found'
        return jsonify(error_code=error_code, error_message=message_on_screen)

    remove_user_follower(whom_id)

    flash('You are no longer following "%s"' % username)
    message_on_screen = 'You are no longer following', username
    error_code = 200
    return jsonify(error_code=error_code, error_message=message_on_screen)

##Liked messages
@app.route('/api/favorites/create/<id>',methods=['GET','POST'])
@basic_auth.required
def like_message(id):
    """Adds the current message as liked message of the given user."""

    redisClient.zincrby('message_like',cPickle.dumps(id))
    return jsonify(error_message= 'Message Liked',error_code='200')



@app.route('/api/favorites/list', methods=['GET','POST'])
def leaderboards():
    list1=leaderboardImplement()
    message_list=[]
    print"--->",type(list1)
    for data in list1:
        print "Data:", data
        print "Type", type(data)
        messages= mongo.db.messages.find({'_id': ObjectId(str(data))},{'author_id':1,'text':1,'pub_date':1,'email':1,'_id':1})
        for row in messages:
            print "Message tect", row['text']
            message_list.append({'message_id': str(row['_id']), 'text': row['text'], 'pub_date': row['pub_date'],'email': row['email']})



    return jsonify(messages=message_list)


@app.route('/api/favorites/destroy/<message_id>',methods=['GET','POST'])
@basic_auth.required
def unlike_message(message_id):

    print"inside liked msg: ",repr(ObjectId(message_id))


    for value in message_id:
        print "Object id from get message Id",value
    if message_id is None:
        abort(404)

    redisClient.zincrby('message_like',cPickle.dumps(message_id), -1)


    return jsonify(error_message= 'Message UnLiked',error_code='200')


@app.route('/api/statuses/update', methods=['GET', 'POST'])
@basic_auth.required
def add_new_message():
    """Registers a new message for the user."""

    text = request.args.get('text')
    user_key = str(session['user_id'])
    if 'user_id' not in session:
        error_code = 401
        message_on_screen = 'Login first and post a message'
        redirect_url = '/api/statuses/public_timeline'
        return jsonify(error_code=error_code, error_message=message_on_screen, redirect_url=redirect_url)
    if text:
        add_post(text)
        if redisClient.get(user_key):
            print "Record Deleted in API"
            redisClient.delete(user_key)
        flash('Your message was recorded')
        error_code = 200
        message_on_screen = 'Posted a message successfully'
        redirect_url = '/api/statuses/home_timeline'
        return jsonify(error_code=error_code, error_message=message_on_screen, redirect_url=redirect_url)


@app.route('/api/account/verify_credentials', methods=['GET', 'POST', 'DELETE'])
@basic_auth.required
def user_login():
    """Logs the user in."""
    username = request.args.get('username')
    password = request.args.get('password')

    if g.user:
        error_code = 200
        message_on_screen = "You are already logged in"
    # return jsonify(error_code=error_code, message=message_on_screen, redirect_url='/api/statuses/home_timeline',username=username)

    if username != None:
        if request.method == 'GET':
            user_key = username
            if redisClient.get(user_key):
                user = cPickle.loads(redisClient.get(user_key))
            else:
                user = get_user_details(username)
                redisClient.set(user_key, cPickle.dumps(user))
                redisClient.expire(user_key, 60)

            if user is None:
                error_code = 401
                message_on_screen = "Invalid username"
                username = request.args.get('username')
            elif not check_password_hash(user[0].get('pw_hash'),
                                         password):
                error = 'Invalid password'
                error_code = 401
                message_on_screen = "Invalid password"
                username = request.args.get('username')
            else:
                flash('You are logged in')
                session['user_id'] = user[0].get('user_id')
                error_code = 200
                message_on_screen = "You are logged in"

        return jsonify(error_code=error_code, message=message_on_screen, redirect_url='/api/statuses/home_timeline',
                       username=username)
    else:
        session.pop('user_id', None)
        error_code = 200
        message_on_screen = 'You are logged out'
    return jsonify(error_code=error_code, message=message_on_screen, redirect_url='/api/statuses/public_timeline')


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url
