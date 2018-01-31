from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
app = Flask(__name__)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

engine = create_engine('sqlite:///catalog_app.db')
Base.metadata.bind = engine


DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/home')
def home():
    print login_session
    categories = session.query(Category).all()
    items = session.query(Item).all()[::-1][:10]
    return render_template('home.html', categories=categories, items=items, login=login_session)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'username' not in login_session:
        flash("You must be logged in to perform this action")
        return redirect(url_for('login'))
    if request.method == 'POST':
        cat = Category(name = request.form['name'], user_id= login_session['user_id'])
        session.add(cat)
        session.commit()
        new = session.query(Category)[-1]
        return redirect(url_for('show', category_id=new.id))
    return render_template('index.html', login = login_session)

@app.route('/category/<int:category_id>', methods=['GET'])
def show(category_id):
    try:
        cat = session.query(Category).filter_by(id=category_id).one()
        i = session.query(Item).filter_by(category_id=category_id).all()
        return render_template('show.html', c=cat, items=i, login = login_session)
    except:
        return render_template('error.html')
    
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def edit(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("You are not authorized to perform this action")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.query(Category).filter_by(id=category_id).update({
            'name': request.form['name']
        })
        session.commit()
        return redirect(url_for('show', category_id=category_id))
    cat = session.query(Category).filter_by(id=category_id).one()
    return render_template('edit.html', c=cat, login = login_session)

@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
def delete(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("You are not authorized to perform this action")
        return redirect(url_for('home'))
    cat = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(cat)
        session.commit()
        return redirect(url_for('create'))
    return render_template('delete.html', c=cat, login = login_session)
    
@app.route('/categories')
def index():
    cats = session.query(Category).all()
    return render_template('catalogs.html', categories=cats, login = login_session)
    
@app.route('/category/<int:category_id>/create_item', methods=['GET', 'POST'])
def create_item(category_id):
    cat = session.query(Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        flash("You must be logged in to perform this action")
        return redirect(url_for('login'))
    if request.method == 'POST':
        item = Item(name = request.form['name'],
                    description = request.form['description'],
                    category_id = category_id,
                    user_id = login_session['user_id'])
        session.add(item)
        session.commit()
        new = session.query(Item)[-1]
        return redirect(url_for('show_item', category_id=category_id, item_id=new.id))
    return render_template('create_item.html', c=cat, login = login_session)

@app.route('/category/<int:category_id>/item/<int:item_id>', methods=['GET'])
def show_item(category_id, item_id):
    try:
        cat = session.query(Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id).one()
        return render_template('show_item.html', c=cat, i=item, login = login_session)
    except:
        return render_template('error.html')

@app.route('/category/<int:category_id>/item/<int:item_id>/edit', methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    print [u.name for u in session.query(User).all()]
    creator = getUserInfo(item.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("You are not authorized to perform this action")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.query(Item).filter_by(id=item_id).update({
            'description': request.form['description'],
            'name': request.form['name']})
        session.commit()
        return redirect(url_for('show_item', category_id=category_id, item_id=item_id))
    cat = session.query(Category).filter_by(id=category_id).one()
    return render_template('edit_item.html', c=cat, i=item, login = login_session)

@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(item.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("You are not authorized to perform this action")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('index'))
    return render_template('delete_item.html', i=item, login = login_session)
    
@app.route('/items')
def items_index():
    i = session.query(Item).all()
    return render_template('items.html', items=i, login = login_session)
    
@app.route('/categories/json')
def categoriesjson():
    json_dict = []
    categories = session.query(Category).all()
    for c in range(0, len(categories)-1):
        cat = categories[c]
        json_dict.append(cat.serialize)
        json_dict[c]['items'] = []
        items = session.query(Item).filter_by(category_id=cat.id).all()
        for i in items:
            json_dict[c]['items'].append(i.serialize)
    return jsonify(categories=json_dict)

@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, login = login_session)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    login_session.clear()
    flash("You have been logged out!")
    return redirect(url_for('home'))
    

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    try:
        user = session.query(User).filter_by(id=user_id).one()
    except NoResultFound:
        return redirect(url_for('home'))
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# Dummy placeholders for display


if __name__ == '__main__':
    app.secret_key = 'secret_stuff'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
