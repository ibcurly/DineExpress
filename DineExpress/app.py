# Flask.
from flask import (Flask, render_template, url_for, request, redirect, flash, jsonify)
from functools import wraps
app = Flask(__name__)

# SqlAlchemy.
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import update

# Database.
from database_setup import Base, Restaurant, MenuItem, User
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind=engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Auth.
from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
from flask import make_response

# Libraries.
import dicttoxml


# Helpers.
from pprint import pprint

################## Others
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

	
@login_manager.user_loader
def load_user(user_id):
    return getUserInfo(int(user_id))
    return User.query.get(int(user_id))
	
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])	
	
	
@app.route('/')
def index():
    return render_template('index.html')
	
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = session.query(User).filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_session['user_id'] = user.id
                login_session['username'] = user.username
                # login_user(user, remember=form.remember.data)
                return redirect(url_for('showRestaurants'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        newUser = User(username=form.username.data, email=form.email.data, password=hashed_password)
        session.add(newUser)
        session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)
	
################## Others

	
# User login.
def login_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    if 'username' in login_session:
      return f(*args, **kwargs)
    else:
      flash('Please log in first.')
      return redirect('/login')
  return decorated_function

@app.route('/')
@app.route('/login')
def showLogin():
  state = ''.join(random.choice(string.ascii_uppercase +
    string.digits) for x in range(32))
  login_session['state'] = state
  return render_template('_page.html', title='Hello!', view='login',
    STATE=state)

# User helper functions.
def createUser(login_session):
  newUser = User(username=login_session['username'], email=login_session[
                 'email'], password=login_session['password'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email=login_session['email']).one()
  return user.id

def getUserInfo(user_id):
  user = session.query(User).filter_by(id=user_id).one()
  return user

def getUserID(email):
  try:
    user = session.query(User).filter_by(email=email).one()
    return user.id
  except:
    return None

# Routing: APP
@app.route('/restaurants')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by('id desc').all()
  return render_template('_page.html', title='Restaurant Menus', view='showRestaurants', restaurants=restaurants, login_session=login_session)

@app.route('/restaurants/new', methods=['GET', 'POST'])
@login_required
def newRestaurant():
  if request.method == 'POST':
    restaurant = Restaurant(name = request.form['name'].strip(), user_id = login_session['user_id'])
    session.add(restaurant)
    session.commit()
    flash('Restaurant ' + '"' + restaurant.name + '"' + ' created.')
    return redirect(url_for('showRestaurants'))
  else:
    return render_template('_page.html', title='New Restaurant', view='newRestaurant')

@app.route('/restaurants/edit/<int:restaurant_id>', methods=['GET', 'POST'])
@login_required
def editRestaurant(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  owner = getUserInfo(restaurant.user_id)
  if owner.id != login_session['user_id']:
    flash('You do not have access to edit %s.' % restaurant.name)
    return redirect(url_for('showRestaurants'))
  if request.method == 'POST':
    if request.form['name']:
        restaurant.name = request.form['name'].strip()
    session.add(restaurant)
    session.commit()
    flash('Restaurant ' + '"' + restaurant.name + '"' + ' updated.')
    return redirect(url_for('showRestaurants'))
  else:
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    return render_template('_page.html', title='Edit Restaurant', view='editRestaurant', restaurant=restaurant)

@app.route('/restaurants/delete/<int:restaurant_id>', methods=['GET', 'POST'])
@login_required
def deleteRestaurant(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  owner = getUserInfo(restaurant.user_id)
  if owner.id != login_session['user_id']:
    flash('You do not have access to edit %s.' % restaurant.name)
    return redirect(url_for('showRestaurants'))
  if request.method == 'POST':
    session.delete(restaurant)
    session.commit()
    flash('Restaurant ' + '"' + restaurant.name + '"' + ' deleted.')
    return redirect(url_for('showRestaurants'))
  else:
    return render_template('_page.html', title='Delete Restaurant', view='deleteRestaurant', restaurant=restaurant)

@app.route('/restaurants/<int:restaurant_id>')
@app.route('/restaurants/<int:restaurant_id>/menu')
def showMenu(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  owner = getUserInfo(restaurant.user_id)
  items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).order_by('id desc')
  return render_template('_page.html', title=restaurant.name, view='showMenu', restaurant=restaurant, items=items, owner=owner, login_session=login_session)

@app.route('/restaurants/<int:restaurant_id>/menu/new', methods=['GET', 'POST'])
@login_required
def newMenuItem(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  owner = getUserInfo(restaurant.user_id)
  if owner.id != login_session['user_id']:
    flash('You do not have access to edit %s.' % restaurant.name)
    return redirect(url_for('showRestaurants'))
  if request.method == 'POST':
    newItem = MenuItem(
      name = request.form['name'].strip(),
      description = request.form['description'].strip(),
      course = request.form['course'].strip(),
      price = request.form['price'].strip(),
      restaurant_id = restaurant.id)
    session.add(newItem)
    session.commit()
    flash('Menu item ' + '"' + newItem.name + '"' + ' created.')
    return redirect(url_for('showMenu', restaurant_id=restaurant_id))
  else:
    return render_template('_page.html', title='New Menu Item', view='newMenuItem', restaurant=restaurant)

@app.route('/restaurants/<int:restaurant_id>/menu/edit/<int:menu_item_id>', methods=['GET', 'POST'])
@login_required
def editMenuItem(restaurant_id, menu_item_id):
  restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  owner = getUserInfo(restaurant.user_id)
  if owner.id != login_session['user_id']:
    flash('You do not have access to edit %s.' % restaurant.name)
    return redirect(url_for('showRestaurants'))
  item = session.query(MenuItem).filter_by(id=menu_item_id).one()
  if request.method == 'POST':
    item.name = request.form['name'].strip()
    item.description = request.form['description'].strip()
    item.course = request.form['course'].strip()
    item.price = request.form['price'].strip()
    session.add(item)
    session.commit()
    flash('Menu item ' + '"' + item.name + '"' + ' updated.')
    return redirect(url_for('showMenu', restaurant_id=restaurant_id))
  else:
    return render_template('_page.html', title='Edit Menu Item', view='editMenuItem', restaurant=restaurant, item=item)

@app.route('/restaurants/<int:restaurant_id>/menu/delete/<int:menu_item_id>', methods=['GET', 'POST'])
@login_required
def deleteMenuItem(restaurant_id, menu_item_id):
  restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
  owner = getUserInfo(restaurant.user_id)
  if owner.id != login_session['user_id']:
    flash('You do not have access to edit %s.' % restaurant.name)
    return redirect(url_for('showRestaurants'))
  item = session.query(MenuItem).filter_by(id=menu_item_id).one()
  if request.method == 'POST':
    session.delete(item)
    session.commit()
    flash('Menu item ' + '"' + item.name + '"' + ' deleted.')
    return redirect(url_for('showMenu', restaurant_id=restaurant_id))
  else:
    return render_template('_page.html', title='Delete Menu Item', view='deleteMenuItem', restaurant=restaurant, item=item)

# Routing: JSON
@app.route('/restaurants/json')
def showRestaurantsJSON():
    restaurants = session.query(Restaurant).all()
    json = jsonify(Restaurants=[r.serialize for r in restaurants])
    response = make_response(json, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/restaurants/xml')
def showRestaurantsXML():
    restaurants = session.query(Restaurant).all()
    xml = dicttoxml.dicttoxml([r.serialize for r in restaurants])
    response = make_response(xml, 200)
    response.headers['Content-Type'] = 'application/xml'
    return response

@app.route('/restaurants/<int:restaurant_id>/menu/json')
def restaurantMenuJSON(restaurant_id):
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
    json = jsonify(MenuItems=[i.serialize for i in items])
    response = make_response(json, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/restaurants/<int:restaurant_id>/menu/xml')
def restaurantMenuXML(restaurant_id):
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
    xml = dicttoxml.dicttoxml([i.serialize for i in items])
    response = make_response(xml, 200)
    response.headers['Content-Type'] = 'application/xml'
    return response

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_item_id>/json')
def restaurantMenuItemJSON(restaurant_id, menu_item_id):
    item = session.query(MenuItem).filter_by(id=menu_item_id).one()
    json = jsonify(Item=[item.serialize])
    response = make_response(json, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_item_id>/xml')
def restaurantMenuItemXML(restaurant_id, menu_item_id):
    item = session.query(MenuItem).filter_by(id=menu_item_id).one()
    xml = dicttoxml.dicttoxml([item.serialize])
    response = make_response(xml, 200)
    response.headers['Content-Type'] = 'application/xml'
    return response

@app.route('/restaurants/menu/view/<int:restaurant_id>', methods=['GET', 'POST'])
def viewMenuItem(restaurant_id):	
	return render_template('login.html', title='View Menu Item', view='viewMenuItem', id=restaurant_id)
	
# Run app.
if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host='127.0.0.1', port=5000)
  #app.run(host='0.0.0.0')
