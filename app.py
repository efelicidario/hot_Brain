from flask import Flask,render_template,request, redirect, url_for, session, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from flask_sqlalchemy import SQLAlchemy #for the database
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import jwt
import numpy as np
import pickle

import sys
import datetime
import bcrypt
import traceback
import os

#from tools.eeg import get_head_band_sensor_object, change_user_and_vid, filename#, test #comment out for mac

from db_con import get_db_instance, get_db

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

    #core info
    id = db.Column(db.Integer, primary_key=True) #Identity column for user
    username = db.Column(db.String(20), nullable = False, unique=True) #Username (20 char max, can't be empty, must be unique)
    fname = db.Column(db.String(20), default = "Name") #User's name (20 char max, can be empty)
    lname = db.Column(db.String(20), default = "Last Name") #User's last name (20 char max)
    email = db.Column(db.String(120), unique=True) #user's email (120 char max, must be unique)
    password = db.Column(db.String(80), nullable = False) #Password (80 char max, can't be empty)
    age = db.Column(db.Integer, default = -1) #age of the user this will be used to restrict user from creating an account
    bio = db.Column(db.Text) #Bio (can be empty)
    profile_pic = db.Column(db.String(120), default='default.png') #Profile picture (120 char max, default is default.jpg)
    completed_survey = db.Column(db.Boolean, default=False) #if the user has completed the survey

    #survey answers
    gender = db.Column(db.string(20)) #gender
    race = db.Column(db.string(20)) #race
    religion = db.Column(db.string(20)) #religion
    education = db.Column(db.string(20)) #education
    occupation = db.Column(db.string(20)) #occupation
    hobbies = db.Column(db.string(20)) #hobbies
    personality = db.Column(db.string(20)) #personality
    long_term = db.Column(db.string(20)) #long term goals
    virtual = db.Column(db.Boolean) #virtual?
    social = db.Column(db.Boolean) #social?

    #preferences from survey
    pronoun_pref = db.Column(db.string(20)) #looking for
    age_range = db.Column(db.string(20)) #age range preference
    race_pref = db.Column(db.string(20)) #race preference say wut
    religion_pref = db.Column(db.string(20)) #religion preference
    additonal_info = db.Column(db.string(20)) #additional info
    occupation_pref = db.Column(db.string(20)) #occupation preference
    interaction = db.Column(db.string(20)) #interaction preference

#Signup form
class SignupForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    fname = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    lname = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Email"})
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
    
    #If email exists, give an error
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                "That email already exists. Please choose a different one.")

#Update form
class UpdateForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Email"})
    fname = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "First Name"})
    lname = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Last Name"})
    bio = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Bio"})
    submit = SubmitField("Update")
    
    #If username exists, give an error
    def validate_username(self, username):
        if username.data != current_user.username:
            existing_user_username = User.query.filter_by(
                username=username.data).first()
            if existing_user_username:
                raise ValidationError(
                    "That username already exists. Please choose a different one.")
    
    #If email exists, give an error
    def validate_email(self, email):
        if email.data != current_user.email:
            existing_user_email = User.query.filter_by(
                email=email.data).first()
            if existing_user_email:
                raise ValidationError(
                    "That email already exists. Please choose a different one.")
    
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
    if 'db' not in g:
        g.db = get_db()

    #if 'hb' not in g: #comment for mac
    #    g.hb = get_head_band_sensor_object() #comment out for mac

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
@app.route('/connect') #endpoint
def connect():
    #test() #for testing purposes
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
    return render_template('survey.html')

@app.route('/survey2', methods=['GET', 'POST'])
@login_required
def survey2():
    return render_template('survey2.html')

@app.route('/survey3', methods=['GET', 'POST'])
@login_required
def survey3():
    return render_template('survey3.html')

@app.route('/survey4', methods=['GET', 'POST'])
@login_required
def survey4():
    current_user.completed_survey = True
    return render_template('survey4.html')

#Once the use is logged in, they go to the logged in dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    #if user is new, redirect to survey
    if current_user.age == -1 and current_user.completed_survey == False:
        return redirect(url_for('survey'))
    else:
        return render_template('dashboard.html')

#Page where the user can edit their profile
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateForm()
    image = url_for('static', filename='pics/profile/' + current_user.profile_pic)
    return render_template('account.html', image_file = image, form=form)

#edit the user's profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UpdateForm()
    if form.validate_on_submit():
        #update the user's info
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.fname = form.fname.data
        current_user.lname = form.lname.data
        current_user.bio = form.bio.data
        db.session.commit()
        return redirect(url_for('account'))
    return render_template('edit_profile.html', form=form)

#Page that displays another user's profile
@app.route('/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user_profile(user_id):
    user = User.query.filter_by(id=user_id).first()
    image = url_for('static', filename='pics/profile/' + user.profile_pic)
    return render_template('user.html', image_file = image, user=user)

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
        new_user = User(username=form.username.data,password=hashed_password,lname=
                        form.lname.data,fname=form.fname.data,email=form.email.data)
        #new user is created
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form = form)

@app.route('/video')
def video():
    return render_template('video.html')

@app.route('/video2')
def video2():
    return render_template('video2.html')

@app.route('/match', methods=['GET'])
@login_required
def match():
    #Retrieve all users from the database except the current user
    users = User.query.filter(User.id != session['user_id']).all()

    #calculate compatability for each user while ignoring the -1's
    scores = [(user, compare(current_user, user)) for user in users if compare(current_user, user) != -1]
    #scores = [(user, compare(current_user, user)) for user in users]


    #sort list of users by compatability in tuples in ascending order
    sorted_users = sorted(scores, key=lambda x: x[1], reverse=False)


    return render_template('match.html', sorted_users=sorted_users)


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
        return json_response(status_=500 ,data=ERROR_MSG)
    print("It is:", resp)
    print(type(resp))
    return resp


#this will return the avg percentage of the user's brainwave similarity 
def compare(user1, user2):
    #get the id's
    id1 = user1.id
    id2 = user2.id

    #a percentage
    score = -1

    #now compare for each video
    for i in range(0, 2):
        #get the file names
        filename1 = str(id1) + "_" + str(i) + ".pkl"
        filename2 = str(id2) + "_" + str(i) + ".pkl"

        #open the files if they exist
        if os.path.exists(filename1) and os.path.exists(filename2):
            with open(filename1, 'rb') as file1:
                with open(filename2, 'rb') as file2:
                    #load the data
                    data1 = []
                    data2 = []
                    
                    with open(filename1, 'rb') as f:
                        try:
                            while True:
                                data1.append(pickle.load(f))
                        except EOFError:
                            pass

                    with open(filename2, 'rb') as f:
                        try:
                            while True:
                                data2.append(pickle.load(f))
                        except EOFError:
                            pass

                    #get the score
                    score = euclidean_distance(data1, data2)
        else:
            print("file does not exist")
            return -1

    print("comparing user: ", user1.username, " and user: ", user2.username)
    return score

def euclidean_distance(thang1, thang2):
    avgs = 0
    count = 0

    #parse the data or some shid
    #there are four different types of brainwaves so we need to compare each one
    #delta, theta, alpha, beta

    #for each brainwave
    for i in range(len(thang1)):
        #I guess we can compare one by one and add it to the avgs
        
        #while both index's exist
        if thang1[i] is None or thang2[i] is None:
            if i == 0:
                return -1
            else:
                return avgs

        ###HERE is where we need to parse the data so we can make a numpy array: np.array([0, 0])
        #THIS MIGHT WORK?!
        #o1 = thang1[i].01 - thang2[i].01
        #o2 = thang1[i].02 - thang2[i].02
        #t3 = thang1[i].03 - thang2[i].03
        #t4 = thang1[i].04 - thang2[i].04  
        #array1 = np.array([o1, o2])
        #array2 = np.array([t3, t4])

        array1 = np.array(thang1[i])
        array2 = np.array(thang2[i])

        #print("array1: ", array1, " array2: ", array2)

        avgs += np.sqrt(np.sum((array1 - array2)**2))
        count += 1

    return (avgs / count)

if __name__ == '__main__':
    db.create_all()
    db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=80)