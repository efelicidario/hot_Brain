from flask import Flask,render_template,request, redirect, url_for, session, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from flask_sqlalchemy import SQLAlchemy #for the database
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import jwt


import sys
import datetime
import bcrypt
import traceback

from tools.eeg import get_head_band_sensor_object #comment out for mac


#from db_con import get_db_instance, get_db

from tools.token_required import token_required

#used if you want to store your secrets in the aws valut
#from tools.get_aws_secrets import get_secrets          #comment/uncomment for test

from tools.logging import logger

ERROR_MSG = "Ooops.. Didn't work!"


#Create our app
app = Flask(__name__)

#connects app file to database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'mewhenthe'

#Bcrypt instance
bcrypt = Bcrypt(app)

#Creates the database instance
db = SQLAlchemy(app)
app.app_context().push()


login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = "login"

#reload user from stored id in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)#Identity column for user
    username = db.Column(db.String(20), nullable = False, unique=True)#User's name (20 char max, can't be empty, must be unique)
    password = db.Column(db.String(80), nullable = False)#Password (80 char max, can't be empty)

#class BrainwaveData(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
#    timestamp = db.Column(db.DateTime, nullable = False, default=datetime.datetime.utcnow)
#    brainwave_data = db.Column(db.Text, nullable = False)

#Signup form
class SignupForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Sign Up")
    
#If username exists, give an error
def validate_username(self, username):
    existing_user_username = User.query.filter_by(
        username=username.data).first()
    if existing_user_username:
        raise ValidationError(
            "That username already exists. Please choose a different one.")
    
#Login form
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

FlaskJSON(app)

#g is flask for a global var storage 
def init_new_env():
    #To connect to DB
    #if 'db' not in g:
    #    g.db = get_db()

    if 'hb' not in g: #comment for mac
        g.hb = get_head_band_sensor_object() #comment out for mac

    #g.secrets = get_secrets()
    #g.sms_client = get_sms_client()
    #g.secrets = get_secrets()
    #g.sms_client = get_sms_client()

#This gets executed by default by the browser if no page is specified
#So.. we redirect to the endpoint we want to load the base page
@app.route('/') #endpoint
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

#This gets exeduted when connect is clicked
@app.route('/connect.html') #endpoint
def connect():
    return render_template('connect.html')

#This is the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['user_id'] = user.id
                session['user_name'] = user.username
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/survey', methods=['GET', 'POST'])
@login_required
def survey():
    user_id = session.get('user_id')
    username = session.get('user_name')
    return render_template('survey.html', user_id = user_id, username = username)

#Once the use is logged in, they go to the logged in dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = session.get('user_id')
    username = session.get('user_name')
    return render_template('dashboard.html', user_id = user_id, username = username)

#Page where the user can edit their profile
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('account.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#This is the Signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        #creates hashed password to encrypt it
        hashed_password= bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,password=hashed_password)
        #new user is created
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form = form)

@app.route('/video')
def video():
    return render_template('video.html')


@app.route("/secure_api/<proc_name>",methods=['GET', 'POST'])
@token_required
def exec_secure_proc(proc_name):
    logger.debug(f"Secure Call to {proc_name}")

    #setup the env
    init_new_env()

    #see if we can execute it..
    resp = ""
    try:
        fn = getattr(__import__('secure_calls.'+proc_name), proc_name)
        resp = fn.handle_request()
    except Exception as err:
        ex_data = str(Exception) + '\n'
        ex_data = ex_data + str(err) + '\n'
        ex_data = ex_data + traceback.format_exc()
        logger.error(ex_data)
        return json_response(status_=500 ,data=ERROR_MSG)

    return resp



@app.route("/open_api/<proc_name>",methods=['GET', 'POST'])
def exec_proc(proc_name):
    logger.debug(f"Call to {proc_name}")
    print("here lol")

    #setup the env
    init_new_env()

    #see if we can execute it..
    resp = ""
    try:
        fn = getattr(__import__('open_calls.'+proc_name), proc_name)
        resp = fn.handle_request()
    except Exception as err:
        ex_data = str(Exception) + '\n'
        ex_data = ex_data + str(err) + '\n'
        ex_data = ex_data + traceback.format_exc()
        logger.error(ex_data)
        print("here lol2")
        return json_response(status_=500 ,data=ERROR_MSG)
    print("It is:", resp)
    print(type(resp))
    return resp


if __name__ == '__main__':
    db.create_all()
    db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=80)
