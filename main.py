from flask import Flask, render_template, request, redirect, url_for, session, g,jsonify, abort,render_template_string,flash,make_response
import urllib, urllib.parse
import warnings
from datetime import date
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, TEXT,DECIMAL,text, DATE
import os
import os.path
import random
with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_mail import Mail, Message
# from Forms import ResetForm
from flask_autoindex import AutoIndex
from flask import json
from werkzeug.exceptions import HTTPException
import functools
from datetime import timedelta
from email.mime.text import MIMEText
import smtplib
import base64
from wtforms.fields.html5 import EmailField
import onetimepass #this
import pyqrcode #this
from io import BytesIO
from flask_bootstrap import Bootstrap #this
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import Length, EqualTo, DataRequired, Email
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import html
import logging



app = Flask(__name__)
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')

file_handler = logging.FileHandler('Activity.log')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'toiletshop.db')
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/myaspj3/mysite/toiletshop.db'
# app.config['JWT_SECRET_KEY'] = 'super-secret' #change
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=2)
import re
# SESSION_COOKIE_SECURE = True
# # use for https
# app.config['SESSION_COOKIE_SECURE']=True
# #cant log in if thru http
# app.config['SESSION_COOKIE_HTTPONLY']=True
# app.config['SESSION_COOKIE_SAMESITE']='Lax'
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
#mail
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'readan999@gmail.com'
app.config['MAIL_PASSWORD'] = 'wrsshovpluevyelj'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
# #
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)
mail = Mail(app)
app.secret_key = os.urandom(24)
bootstrap = Bootstrap(app)
limiter = Limiter(app, key_func=get_remote_address)


def db_create():
    db.create_all()
    print("Database created.")

def db_drop():
    db.drop_all()
    print("Database dropped.")


#Database models
class User(db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String(64), index=True)
    password_hash = Column(String(128))
    otp_secret = Column(String(16))
    is_admin = Column(String)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Auth:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.email, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    def get_reset_token(self, expires_sec=600): #10 mins
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'first_name', 'last_name', 'email', 'password','otp_secret','is_admin')
#
class ItemsSchema(ma.Schema):
    class Meta:
        fields = ('item_id', 'item_image', 'item_name', 'item_desc', 'item_price', 'item_stock')


class UserCartSchema(ma.Schema):
    class Meta:
        fields = ('item_id', 'item_image', 'item_name', 'item_desc', 'item_price', 'item_stock', 'user_id')


class UserPaymentSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'name', 'email', 'address', 'city', 'state',
                  'zip', 'creditName', 'cardNum', 'expireMonth',
                  'expireYear', 'cvv')


class UserOrderSchema(ma.Schema):
    class Meta:
        fields = (
            'user_id', 'order_item_id', 'item_image', 'item_name', 'item_desc', 'item_price', 'item_quantity', 'date')


user_schema = UserSchema()
users_schema = UserSchema(many=True)

item_schema = ItemsSchema()
items_schema = ItemsSchema(many=True)

cart_schema1 = UserCartSchema()
cart_schema = UserCartSchema(many=True)

payments_schema = UserPaymentSchema(many=True)
orders_schema = UserOrderSchema(many=True)


class Reviews(db.Model):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer)
    username = Column(String)
    content = Column(TEXT)

class Items(db.Model):
    __tablename__ = "items"
    item_id = Column(Integer, primary_key=True)
    item_image = Column(String)
    item_name = Column(String)
    item_desc = Column(TEXT)
    item_price = Column(DECIMAL(6,2))
    item_stock = Column(Integer)

class UserCart(db.Model):
    user_id = text('A163216549')
    __tablename__ = user_id  # get login user id
    item_id = Column(Integer, primary_key=True)
    item_image = Column(String)
    item_name = Column(String)
    item_desc = Column(TEXT)
    item_price = Column(DECIMAL(6, 2))
    item_stock = Column(Integer)


class UserPayment(db.Model):
    __tablename__ = "PaymentInfo"  # get login user id
    user_id = Column(String, primary_key=True)
    name = Column(String)
    email = Column(String)
    address = Column(String)
    city = Column(String)
    state = Column(String)
    zip = Column(Integer)
    creditName = Column(String)
    cardNum = Column(Integer)  # 4539579803742677850
    expireMonth = Column(String)
    expireYear = Column(Integer)
    cvv = Column(Integer)


class UserOrder(db.Model):
    __tablename__ = "Order"  # get login user id
    user_id = Column(Integer)
    order_item_id = Column(Integer, primary_key=True)
    item_image = Column(String)
    item_name = Column(String)
    item_desc = Column(TEXT)
    item_price = Column(DECIMAL(6, 2))
    item_quantity = Column(Integer)
    date = Column(String)


def db_seed():
    toiletpaper = Items(item_image = 'toiletpaper',
                    item_name='Toilet Paper',
                    item_desc='A thin sanitary absorbent paper usually in a roll for use in drying or cleaning oneself after defecation and urination. Soft 3ply toilet paper, feels nice against your anus',
                    item_price=7.00,
                    item_stock=150)

    toothpaste = Items(item_image = 'toothpaste',
                    item_name='Toothpaste',
                    item_desc='A paste dentifrice used with a toothbrush to clean and maintain the aesthetics and health of teeth, Mint flavored keeping your breath fresh',
                    item_price=5.50,
                    item_stock=200)

    toothbrush = Items(item_image = 'toothbrush',
                    item_name='Toothbrush',
                    item_desc='An oral hygiene instrument used to clean the teeth, gums, and tongue. Utilized with toothpaste',
                    item_price=2.50,
                    item_stock=200)

    shampoo = Items(item_image = 'shampoo',
                    item_name='Shampoo',
                    item_desc='Shampoo is a hair care product, in the form of a viscous liquid, that is used for cleaning hair during showers',
                    item_price=12.00,
                    item_stock=300)

    razor = Items(item_image = 'razor',
                    item_name='Manual razor',
                    item_desc='A razor is used to remove small hairs such as beards, leg hair, pubic hair, etc.',
                    item_price=20.00,
                    item_stock=100)

    db.session.add(toiletpaper)
    db.session.add(toothpaste)
    db.session.add(toothbrush)
    db.session.add(shampoo)
    db.session.add(razor)

    review1 = Reviews(item_id=2,
                     username="Testuser1",
                     content='This product is amazing! Cheap and good')

    review2 = Reviews(item_id=2,
                 username="Testuser2",
                 content='This product is bad! not worth!')

    review3 = Reviews(item_id=4,
                 username="Testuser3",
                 content='Great item! very nice i like it')

    db.session.add(review1)
    db.session.add(review2)
    db.session.add(review3)
    # password = 'P@ssw0rd'
    # password=generate_password_hash(password,method='sha256'))
    admin = User(first_name='Null',
                 last_name='Null',
                 email='mrnimda@toilet.org',
                 password='admin',
                 is_admin='True')
                 #  email='admin@toilet.org',
                 # password=generate_password_hash(password,method='sha256'))

    user = User(first_name='user',
                 last_name='toilet',
                 email='user@toilet.org',
                 password='P@55word',
                 is_admin='False')

    db.session.add(user)
    db.session.add(admin)
    db.session.commit()
    print('Database seeded.')

# db_drop()
# db_create()
# db_seed()

class RegisterForm(FlaskForm):
    """Registration form."""
    first_name = StringField('First Name', validators=[DataRequired(), Length(1, 10)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(1, 10)])
    email = EmailField('Email', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Password again',
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """Login form."""
    email = EmailField('Email', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Password', validators=[DataRequired()])
    token = StringField('Token', validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField('Login')

class AdminLoginForm(FlaskForm):
    """Login form."""
    email = EmailField('Email', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ResetForm(FlaskForm):

    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


    def validate_email(self, email):

        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

@app.errorhandler(404)
def page_not_found(error):
    # print(basedir)
    # template = '''
    # <h1>That page doesn't exist.</h1>
    # <h3>%s Not found</h3>''' #% (urllib.parse.unquote(request.url))
    # print(request.url)
    # template = '''<h2>Hello {}!</h2>'''.format(urllib.parse.unquote(request.url))
    # return render_template_string(template, dir=dir, help=help, locals=locals), 404
    msg = Message(subject='Path Traversal attack', sender='testingnachos@gmail.com', recipients=['sbxiaobao@gmail.com'])
    mail.send(msg)
    if g.user:
        logger.warning(
            ':User_Name:{} 404 Error:{} Route: {} IP: {}'.format(g.user, error, request.url, request.remote_addr))
    else:
        logger.warning('404 Error:{} Route:{} IP: {}'.format(error, request.url, request.remote_addr))
    return render_template('404.html')

@app.errorhandler(401)
def page_not_foundd(e):
    return redirect('/')

@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response



@app.route("/", methods=['GET', 'POST'])
def store():
    # db_drop()
    # db_create()
    # db_seed()

    if request.method == 'POST':
        if 'user' in session:
            contentt = request.form['comment']
            item_idd = request.form.get("item_idd","")
            # statement = text('INSERT INTO reviews ("item_id","username","content") VALUES ("'+item_idd+'","'+request.cookies.get('username')+'","'+contentt+'")')
            # db.engine.execute(statement)

            #fix
            #first fix, xss, injection
            # blacklist=['<script>','{{','}}',"1=1",'=']
            # for i in blacklist:
            #     if i in contentt:
            #         flash('invalid review, review not submitted')
            #         redirect('/')

            #second fix

            # review = Reviews(item_id=item_idd,
            #      username=request.cookies.get('username'),
            #      content=contentt)
            # db.session.add(review)
            # db.session.commit()
            #3rd fix

            statement = text('INSERT INTO reviews ("item_id","username","content") VALUES (:a ,:b ,:c)')
            db.engine.execute(statement,a=item_idd,b=request.cookies.get('username'),c=contentt)
            #endfix
            return redirect('/')
        else:
            flash("Please sign in first")
    search_query = request.args.get('q')
    print("search query:", search_query)
    items_list = []
    get_all_items = text('SELECT * FROM items')
    result = db.engine.execute(get_all_items).fetchall()
    print(result)

    for (row) in result:
        print("hellooo")
        print(row[2])
        print(search_query)
        print("end hellooo")
        if search_query is None or search_query.upper() in row[2].upper():
            items_list.append(row)

    print(items_list)
    review_list = []
    get_all_reviews = text('SELECT * FROM reviews')
    result2 = db.engine.execute(get_all_reviews).fetchall()
    for (rev) in result2:
        review_list.append(rev)
    print(review_list)


    return render_template('store.html',items_list=items_list,
                       search_query=search_query, review_list=review_list)


# @app.route('/addItem/<int:item_id>', methods=['GET', 'POST'])
# def addItem(item_id: int):
#     # db_create()
#     user_id = text('A163216549')
#     item = UserCart.query.filter_by(item_id=item_id).first()
#     if item:
#         return jsonify("There is an item in your cart already"), 409
#     else:
#         get_all_items = text('SELECT * FROM items')
#         result = db.engine.execute(get_all_items).fetchall()
#         for i in result:
#             if i[0] == item_id:
#                 item_id = i[0]
#                 item_image = i[1]
#                 item_name = i[2]
#                 item_desc = i[3]
#                 item_price = i[4]
#                 item_stock = 1
#                 usercart = UserCart(item_id=item_id, item_image=item_image, item_name=item_name,
#                                     item_desc=item_desc,
#                                     item_price=item_price, item_stock=item_stock)
#                 db_create()
#                 db.session.add(usercart)
#                 db.session.commit()
#                 return redirect('/')
#             else:
#                 pass


# @app.route('/deleteItem/<int:item_id>', methods=['DELETE', 'POST'])
# def deleteItem(item_id: int):
#     item = UserCart.query.filter_by(item_id=item_id).first()
#     if item:
#         print(item)
#         db.session.delete(item)
#         db.session.commit()
#         return render_template('cart.html')
#     else:
#         return jsonify(message="That item does not exist"), 404

# #
# @app.route('/cart')
# def cart():
#     cart_list = []
#     user_id = 'A163216549'
#     a = ('SELECT * FROM ' + user_id)
#     print(a)
#     get_all_items = text(a)
#     result = db.engine.execute(get_all_items).fetchall()
#     for item in result:
#         print(item)
#         cart_list.append(item)
#         # print(item['item_id'])
#     # print(cart_list)

#     total = 0
#     for item in cart_list:
#         total += item['item_price']
#     return render_template('cart.html', cart_list=cart_list, total=total)


# @app.route('/checkOut', methods=["GET", "POST"])
# def checkOut():
#     user_id = 'A163216549'
#     checkOutCart = []
#     a = ('SELECT * FROM ' + user_id)
#     get_all_items = text(a)
#     result = db.engine.execute(get_all_items).fetchall()
#     for item in result:
#         print(item)
#         checkOutCart.append(item)

#     total = 0
#     for item in checkOutCart:
#         total += item['item_price']

#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         address = request.form['address']
#         city = request.form['city']
#         state = request.form['state']
#         zip = request.form['zip']
#         creditName = request.form['cardname']
#         cardNum = request.form['cardnumber']  # 4539579803742677850
#         expireMonth = request.form['expmonth']
#         expireYear = request.form['expyear']
#         cvv = request.form['cvv']
#         all = UserPayment.query.all()
#         all_payment = payments_schema.dump(all)
#         exist = False
#         for a in all_payment:
#             if a['user_id'] == user_id:
#                 exist = True
#         if exist:
#             pass
#         else:
#             paymentInfo = UserPayment(user_id=user_id, name=name, email=email, address=address, city=city,
#                                       state=state,
#                                       zip=zip, creditName=creditName, cardNum=cardNum, expireMonth=expireMonth,
#                                       expireYear=expireYear, cvv=cvv)
#             db.session.add(paymentInfo)
#             db.session.commit()

#         for item in result:
#             print(item)
#             if item:
#                 today = date.today()
#                 order = UserOrder(user_id=user_id, order_item_id=random.randint(99999999999999, 999999999999999),
#                                   item_image=item['item_image'], item_name=item['item_name'],
#                                   item_desc=item['item_desc'], item_price=item['item_price'],
#                                   item_quantity=item['item_stock'], date=today)
#                 # db_create()
#                 db.session.add(order)
#                 db.session.commit()
#         print(name, email, address, city, state, zip, creditName, cardNum, expireMonth, expireYear, cvv)
#         items = UserCart.query.all()
#         for i in items:
#             db.session.delete(i)
#         db.session.commit()
#         return redirect('/')

#     return render_template('checkOut.html', user_id=user_id, checkOutCart=checkOutCart, total=total)

@app.route('/orders')
def orders():
    user_id = 'A163216549'
    orderCart = []
    allOrder = UserOrder.query.all()
    result = orders_schema.dump(allOrder)
    for item in result:
        if item['user_id'] == user_id:
            orderCart.append(item)

    return render_template('orders.html', orderCart=orderCart)


@app.route('/info')
def info():
    return render_template('info.html')


@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']
        if 'is_admin' in session:
            g.role = session['is_admin']

def login_required(func):
    @functools.wraps(func)
    def secure_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))

        return func(*args, **kwargs)

    return secure_function

files_index = AutoIndex(app, browse_root=os.path.curdir , add_url_rules=False)


# Custom indexing
@app.route('/dir')
@app.route('/dir/<path:path>')
@login_required
def autoindex(path='.'):
    if g.user:
        if 'user' in session:
            # if session['user'] == 'admin@toilet.org': #admin needs to change pass/new email also
            if session['is_admin'] == 'True':
                return files_index.render_autoindex(path)
            else:
                abort(403)



@app.route("/logout")
def logout():
    # session.pop('user', None)
    session.clear()
    print("User logged out.")
    #return render_template('store.html')
    resp = make_response(redirect('/'))
    resp.delete_cookie('username')
    return resp

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('Email already exists.')
            print('Email already exist.')
            return redirect(url_for('register'))
        else:
            password = form.password.data
            if len(password) < 8:
                flash('Password is too short!')
                return redirect(url_for('register'))

            elif not any(char.isdigit() for char in password):
                flash('Password must contain a digit!')
                return redirect(url_for('register'))

            elif not any(char.isupper() for char in password):
                flash('Password must contain uppercase!')
                return redirect(url_for('register'))

            elif not re.search("[$#@]",password):
                flash('Password must contain unique characters!')
                return redirect(url_for('register'))
        # add new user to the database
        user = User(first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    email=form.email.data,
                    password=form.password.data,
                    is_admin=False)
        print('user added',user)
        db.session.add(user)
        db.session.commit()

        # redirect to the two-factor auth page, passing username in session
        session['2fa'] = user.email
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)

@app.route('/twofactor')
def two_factor_setup():
    if '2fa' not in session: #maybe? if not change to user
        return redirect(url_for('store'))
    user = User.query.filter_by(email=session['2fa']).first()
    if user is None:
        return redirect(url_for('store'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if '2fa' not in session:
        abort(404)
    user = User.query.filter_by(email=session['2fa']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['2fa']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/admin_info', methods=['GET'])
def admin_info():
    if g.user:
        if 'user' in session:
                #only admin can access
            if session['is_authenticated'] == 'True':
                 ##insert admin page here
                #follow this format for all admin def
                print("ADMIN PAGE")
                user_list = User.query.all()
                result = users_schema.dump(user_list)
                return jsonify(result)
            else:
                return redirect(url_for('store'))
        else:
            return redirect(url_for('store'))
    else:
        return redirect(url_for('store'))
    #  if g.user:
    #     if 'user' in session:
    #             #only admin can access
    #         if session['is_admin'] == 'True':
    #              ##insert admin page here
    #             #follow this format for all admin def
    #             print("ADMIN PAGE")
    #             user_list = User.query.all()
    #             result = users_schema.dump(user_list)
    #             return jsonify(result)

    #  else:
    #      abort(403)
    #             #for admin access only

@app.route('/getpagenimda')
def admin():
    if g.user:
      if 'user' in session:
        if session['is_admin'] == 'True':
             return render_template('admin.html')
        else:
            return redirect(url_for('store'))
      else:
       return render_template('login.html')
    else:
       return render_template('login.html')
    # if 'user' in session:
    #     if session['is_admin'] == 'True':
    #         return render_template('admin.html')
    #     else:
    #         abort(401)
    # else:
    #     abort(401)


@app.route('/secret/tos')
def tos():
    return render_template('tos.html')
    # if g.user:
    #     if 'user' in session:
    #         if session['user'] == 'admin@toilet.org':
    #             return render_template('admin.html')
    #         else:
    #             abort(403)
    #
    # return redirect(url_for('login'))

@app.route('/secret')
def secret():
    return render_template('logo.html')


# create admin token from here if new db is created
# @app.route('/adminlogin', methods=['GET', 'POST'])
# def adminlogin():
#     form = AdminLoginForm()
#     if form.validate_on_submit():
#         session.pop('user', None)
#         user = User.query.filter_by(email=form.email.data).first()
#         if user is None or not user.verify_password(form.password.data):
#             flash('Not admin email')
#             return redirect(url_for('adminlogin'))
#         if user.is_admin==False:
#             user.is_admin=True
#             print("User is now..",user.is_admin)
#             return redirect(url_for('login'))

#         print("User is now..",user.is_admin)
#         # log user in
#         session['2fa'] = user.email
#         return redirect(url_for('two_factor_setup'))
#     return render_template('adminlogin.html', form=form)

@app.route('/login/', methods=['GET', 'POST'])
@limiter.limit("5/minute") #5 request per min
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if request.cookies.get('fc'):
            if int(request.cookies.get('fc'))>5:
                flash('max number of attempts reached')
                return redirect(url_for('login'))
        session.pop('user', None)
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            resp = make_response(redirect(url_for('login')))
            logger.info('User_Name:{} Incorrect username/password'.format(form.email.data))
            print(user.verify_totp(form.token.data))
            flash('Invalid email, password or token.')
            if request.cookies.get('fc'):
                num= int(request.cookies.get('fc'))+1
                resp.set_cookie('fc', str(num), httponly=True, secure=True)
            else:
                resp.set_cookie('fc', '0', httponly=True, secure=True)
            return resp

        # log user in
        statement = text('SELECT * FROM users WHERE email=:i')
        user_detail= db.engine.execute(statement,i = str(form.email.data)).fetchone()
        print("id: 0", user_detail[0])
        print("user to see who is signed in: 3", user_detail[3])
        print("firstname: 1", user_detail[1])
        print("lastname: 1", user_detail[2])
        print("is authenticated is...5: ", user_detail[5])


        # session['user'] = user.email
        # session['user'] = user.email
        session['id'] = user_detail[0]
        session['user']= user_detail[3]
        session['name'] = user_detail[1]
        print("Test session:" ,session['user'])


        session['is_admin'] = user_detail[6]
        session.permanent = True
        if user_detail[6] == 'True':
            #blah blah blah whatever admin needs to be diff
            resp = make_response(redirect('/getpagenimda'))
        else:
            resp = make_response(redirect('/'))
        name = user_detail[1]+user_detail[2]
        resp.set_cookie('username', name, httponly=False, secure=True)
        print(session['id'])
        print(session['is_admin'])
        return resp
        flash('You are now logged in!')
        return redirect(url_for('store'))
    return render_template('login.html', form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    demo = 'readan999@gmail.com'
    msg = Message('Password Reset Request',
                  sender='noreply@toilet.com',
                  # recipients='readan999@gmail.com')

                  recipients=[demo])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/forgotpassword", methods=['GET', 'POST'])
def reset_request():

    form = ResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
        user = User.verify_reset_token(token)
        if user is None:
            flash('That is an invalid or expired token', 'warning')
            return redirect(url_for('reset_request'))
        form = ResetPasswordForm()
        if form.validate_on_submit():
            password = form.password.data
            if len(password) < 8:
                flash('Password is too short!')
                return redirect(url_for('reset_request'))

            elif not any(char.isdigit() for char in password):
                flash('Password must contain a digit!')
                return redirect(url_for('reset_request'))

            elif not any(char.isupper() for char in password):
                flash('Password must contain uppercase!')
                return redirect(url_for('reset_request'))

            elif not re.search("[$#@]",password):
                flash('Password must contain unique characters!')
                return redirect(url_for('reset_request'))
            user.password = form.password.data
            db.session.commit()
            flash('Your password has been updated! You are now able to log in', 'success')
            return redirect(url_for('login'))
        return render_template('reset_token.html', title='Reset Password', form=form)


@app.route('/account',methods=['GET', 'POST','PUT'])
def account():
    id = str(session['id'])
    statement = text('SELECT * FROM users WHERE id =:i')
    result = db.engine.execute(statement,i = id).fetchone()
    print(result.email)
    print(result[0])

    user = User.query.filter_by(id=id).first()
    print(user.first_name,user.last_name,user.is_admin)
    if user:
        if request.method == "POST":
            user.first_name = request.form['first_name']
            user.last_name = request.form['last_name']
            # user.is_admin = request.form['is_admin']
            db.session.commit()
            print(result)
            return render_template('account.html', result=result)
    return render_template('account.html',result=result)
    # return render_template('account.html',id = session['id'])
    # return redirect(url_for('login'))

@app.route('/cust_details/<int:cust_id>', methods=['GET', 'POST'])
def cust_details(cust_id: int):
    statement = text('SELECT * FROM users WHERE id =:c')
    result = db.engine.execute(statement,c=str(cust_id)).fetchone()
    if g.user:
        if 'user' in session:
                #for normal user to access
            if session['is_authenticated'] == 'False':
                 ##insert admin page here
                #follow this format for all admin def
                 print(result)
                 id = result[0]
                 name = result[1] + result[2]
                 email = result[3]
                 password = generate_password_hash(result[4], method='sha256')
                 password_display = password
                 return render_template('info.html',id=id,name=name,email=email,password=password_display)

            else:
                abort(403)
                #for normal user to access
    # statement = text('SELECT * FROM users WHERE id =:c')
    # result = db.engine.execute(statement,c=str(cust_id)).fetchone()
    # if result == None:
    #     abort(401)
    #     return redirect('/')
    # else:
    #     print(result)
    #     id = result[0]
    #     name = result[1] + result[2]
    #     email = result[3]
    #     password = generate_password_hash(result[4], method ='sha256')
    #     password_display = password
    #     return render_template('info.html',id=id,name=name,email=email,password=password_display)




if __name__ == '__main__':
        app.run()
    # app.run(debug=True, host="127.0.0.1", port=80)
