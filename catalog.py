from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask import flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

engine = create_engine('sqlite:///catalog_app.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/home')
def home():
    sesh = session.query(Category)
    categories = session.query(Category).all()
    items = session.query(Item).all()[::-1][:10]
    return render_template('home.html', categories=categories, items=items,
                            login=login_session, sesh=sesh)


@app.route('/create', methods=['GET', 'POST'])
def create():
    """Category create page"""
    
    # Confirm that the current user is both authenticated and has proper
    # authorization
    
    if 'username' not in login_session:
        flash("You must be logged in to perform this action")
        return redirect(url_for('login'))
    if request.method == 'POST':
        cat = Category(name=request.form['name'],
                        user_id=login_session['user_id'])
        session.add(cat)
        session.commit()
        new = session.query(Category)[-1]
        return redirect(url_for('show', category_id=new.id))
    return render_template('index.html', login=login_session)


@app.route('/category/<int:category_id>', methods=['GET'])
def show(category_id):
    try:
        cat = session.query(Category).filter_by(id=category_id).one()
        i = session.query(Item).filter_by(category_id=category_id).all()
        return render_template('show.html', c=cat, items=i,
                                login=login_session)
    except:
        return render_template('error.html')


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def edit(category_id):
    """Category edit page"""
    
    category = session.query(Category).filter_by(id=category_id).one()
    
    # Confirm that the current user is both authenticated and has proper
    # authorization
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
    return render_template('edit.html', c=cat, login=login_session)


@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
def delete(category_id):
    """Category delete page"""
    
    category = session.query(Category).filter_by(id=category_id).one()
    # Confirm that the current user is both authenticated and has proper
    # authorization
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("You are not authorized to perform this action")
        return redirect(url_for('home'))
    cat = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=cat.id)
    if request.method == 'POST':
        session.delete(cat)
        # Make sure that each item associated with the category being deleted,
        # also gets deleted
        for i in items:
            session.delete(i)
        session.commit()
        return redirect(url_for('home'))
    return render_template('delete.html', c=cat, login=login_session)


@app.route('/categories')
def index():
    cats = session.query(Category).all()
    return render_template('catalogs.html', categories=cats,
                        login=login_session)


@app.route('/category/<int:category_id>/create_item', methods=['GET', 'POST'])
def create_item(category_id):
    """Crete item page"""
    
    cat = session.query(Category).filter_by(id=category_id).one()
    # Confirm that the current user has proper authorization
    if 'username' not in login_session:
        flash("You must be logged in to perform this action")
        return redirect(url_for('login'))
    if request.method == 'POST':
        item = Item(name=request.form['name'],
                    description=request.form['description'],
                    category_id=category_id,
                    user_id=login_session['user_id'])
        session.add(item)
        session.commit()
        new = session.query(Item)[-1]
        return redirect(url_for('show_item', category_id=category_id,
                        item_id=new.id))
    return render_template('create_item.html', c=cat, login=login_session)


@app.route('/category/<int:category_id>/item/<int:item_id>', methods=['GET'])
def show_item(category_id, item_id):
    """Item show page"""
    # Make sure that the item or category in question actually exists in the
    # database
    try:
        cat = session.query(Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id).one()
        return render_template('show_item.html', c=cat, i=item,
                                login=login_session)
    except:
        return render_template('error.html')


@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
            methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    """Item edit page"""
    
    item = session.query(Item).filter_by(id=item_id).one()
    
    # Confirm that the current user is both authenticated and has proper
    # authorization
    creator = getUserInfo(item.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("You are not authorized to perform this action")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.query(Item).filter_by(id=item_id).update({
            'description': request.form['description'],
            'name': request.form['name']})
        session.commit()
        return redirect(url_for('show_item', category_id=category_id,
                        item_id=item_id))
    cat = session.query(Category).filter_by(id=category_id).one()
    return render_template('edit_item.html', c=cat, i=item, login=login_session)


@app.route('/category/<int:category_id>/item/<int:item_id>/delete', methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    """Confirmation page before deleting an item"""
    item = session.query(Item).filter_by(id=item_id).one()
    # Confirm that the current user is both authenticated and has proper
    # authorization
    creator = getUserInfo(item.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("You are not authorized to perform this action")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('show', category_id=category_id))
    return render_template('delete_item.html', i=item, login=login_session)


@app.route('/items')
def items_index():
    i = session.query(Item).all()
    return render_template('items.html', items=i, login=login_session)


@app.route('/categories/json')
def categoriesjson():
    """In order to set up the JSON endpoint, both Category and Item classes in
    the database have been modified to be serializable. In order to also in-
    clude the associated items for each category, some custom code could be
    written."""
    # First set up an empty array
    json_dict = []
    categories = session.query(Category).all()
    # Loop through all categories with an index
    for c in range(0, len(categories)-1):
        # store each category in a variable
        cat = categories[c]
        # append the serialized category
        json_dict.append(cat.serialize)
        # create an empty array within the hash as 'Items'
        json_dict[c]['items'] = []
        # retrieve all items associated with the current category
        items = session.query(Item).filter_by(category_id=cat.id).all()
        # loop through the items and append the serialized format to the items
        # array within the hash
        for i in items:
            json_dict[c]['items'].append(i.serialize)
    return jsonify(categories=json_dict)


@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, login=login_session)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # confirm that the token is authentic and originating from where the
    # request says it is. This is done in order to prevent forgeries and similar
    # attacks
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    
    # retrieve the app id and the app secret from the fb clients json filed
    # in the directory. Then process the GET request using http2lib
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
    token = result.split(',')[0].split(':')[1].replace('"', '')
    
    # set up the url
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
    
    # append the data into the output
    output = ''
    output += '<h1>Welcome, '
    # the username
    output += login_session['username']

    output += '!</h1>'
    # the picture
    output += '<img src="'
    output += login_session['picture']
    output += '>'
    # these will be used to confirm that the user has been logged in, displa-
    # ying the facebook profile photo and the name
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """FB disconnect page"""
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    # use httplib2 to make the delete request
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    # clear the login_session cookie
    login_session.clear()
    # notify the user that they have been successfully logged out
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
    except:
        return redirect(url_for('home'))
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'secret_stuff'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
