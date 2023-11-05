from flask import Flask, flash, render_template, request, redirect, url_for, session, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from flask_sqlalchemy import SQLAlchemy #for the database
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import jwt
import numpy as np
import pickle
from flask_mail import Message#, Mail
#from app import db, mail
import sqlite3
import json
from time import time
from werkzeug.utils import secure_filename
import uuid as uuid
#from twilio.rest import Client
#from keys import account_sid, auth_token, twilio_number

#from itsdangerous import JSONWebSignatureSerializer

import sys
import datetime
import bcrypt
import traceback
import os

#from tools.eeg import get_head_band_sensor_object, change_user_and_vid, filename#, test #comment out for mac

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

#client = Client(account_sid, auth_token)

#Bcrypt instance
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static/user_imgs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#Creates the database instance
db = SQLAlchemy(app)
app.app_context().push()

#chat inttegration
#socketio = SocketIO(app)

login_manager = LoginManager() 
#login_manager = LoginManager(app) 
login_manager.init_app(app)
login_manager.login_view = "login"

# Outlook SMPT Settings
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
#app.config['MAIL_USE_SSL'] = 
app.config['MAIL_USERNAME'] = 'felic017@csusm.edu'
app.config['MAIL_PASSWORD'] = ''

# Google SMPT Settings
#app.config['MAIL_SERVER'] = 'smtp.gmail.com'
#app.config['MAIL_PORT'] = 587
#app.config['MAIL_USE_TLS'] = True
#app.config['MAIL_USE_SSL'] = 
#app.config['MAIL_USERNAME'] = 'teewhylerr@gmail.com'
#app.config['MAIL_PASSWORD'] = ''

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
    phone_number = db.Column(db.String(20)) #phone number, can be empty
    completed_survey = db.Column(db.Boolean, default=False) #if the user has completed the survey
    profile_pic = db.Column(db.String(), nullable=True)
    
    # Create a string
    def __repr__(self):
        return '<Username %r>' % self.username
    
    #survey answers
    gender = db.Column(db.String(20)) #gender
    race = db.Column(db.String(20)) #race
    religion = db.Column(db.String(20)) #religion
    education = db.Column(db.String(20)) #education
    occupation = db.Column(db.String(20)) #occupation
    hobbies = db.Column(db.String(20)) #hobbies
    personality = db.Column(db.String(20)) #personality
    long_term = db.Column(db.String(20)) #long term goals
    virtual = db.Column(db.Boolean) #virtual?
    social = db.Column(db.Boolean) #social?

    #preferences from survey
    pronoun_pref = db.Column(db.String(20)) #looking for
    age_range_min = db.Column(db.String(20)) #age range preference
    age_range_max = db.Column(db.String(20)) #age range preference
    race_pref = db.Column(db.String(20)) #race preference say wut
    religion_pref = db.Column(db.String(20)) #religion preference
    additonal_info = db.Column(db.String(20)) #additional info
    occupation_pref = db.Column(db.String(20)) #occupation preference
    interaction = db.Column(db.String(20)) #interaction preference

    def get_token(self, expires=500):
        return jwt.encode({'reset_password': self.username, 'exp': time() + expires},
                          key=os.getenv('SECRET_KEY_FLASK'))
    #def get_token(self,expires_sec=300):
    #    serial=Serializer(app.config['SECRET_KEY'], expires_in=expires_sec)
    #    return serial.dumps({'user_id':user.id}).decode('utf-8')
    
    @staticmethod
    def verify_token(token):
        try:
            username = jwt.decode(token, key=os.getenv('SECRET_KEY_FLASK'))['reset_password']
            print(username)
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(username=username).first()
    #@staticmethod
    #def verify_token(token):
    #    serial=Serializer(app.config['SECRET_KEY'])
    #    try:
    #        user_id=serial.loads(token)['user_id']
    #    except:
    #        return None
    #    return User.query.get(user_id)

#Signup form
class SignupForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Username"})
    fname = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Username"})
    lname = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Username"})
    phone_number = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Phone Number"})
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Password"})
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
        min=4, max=40)], render_kw={"placeholder": "Username"})
    profile_pic = FileField("Profile Pic")
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Email"})
    fname = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "First Name"})
    lname = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Last Name"})
    bio = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Bio"})
    
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
    

class ResetRequestForm(FlaskForm):
    email = StringField(label="Email",validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Email"})
    submit = SubmitField(label='Reset Password')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Confirm Password"})
    #submit = SubmitField("Login")
    submit = SubmitField(label='Change Password')

FlaskJSON(app)

#g is flask for a global var storage 
def init_new_env():
    #To connect to DB
    if 'db' not in g:
        print("Connecting to DB")

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
                flash("Login successful.")
                return redirect(url_for('dashboard'))
    return render_template('login.html', title='Login', form=form)

def send_email(user):
    #token=user.get_token()
    token=user.get_token()
    msg = Message()
    msg.subject="hotBrain Password Reset"
    msg.sender=os.getenv('MAIL_USERNAME')
    msg.recipients=[user.email]
    #msg = Message('Password Reset Request',recipients=[user.email],sender='noreply@hotbrain.com')
    msg.body=f''' To reset your password. Please follow the link below.
    
    
    {url_for('reset_token',token=token,_external=True)}
    
    If you didn't send a password reset request. Please igore this message.
    
    '''
    mail.send(msg)
    # pass

# Password Reset page
@app.route('/reset_password',methods=['GET', 'POST'])
def reset_request():
    form=ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data)
        user=User.query.filter_by(email=form.email.data).first()
        if user:
            send_email(user)
            # flash('Reset request sent. Check your email.','success')
            return redirect(url_for('login'))
    return render_template('reset_request.html',title='Reset Request',form=form,legend="Reset Password")

@app.route('/reset_password/<token>',methods=['GET', 'POST'])
def reset_token(token): 
    user = User.verify_token(token)
    if user is None:
        #flash('This is an invalid or expired token. Please try again.', 'warning')
        return redirect(url_for('reset_request'))
    
    form=ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password=hashed_password
        db.session.commit()
        #flash('Password changed! Please login.','success')
        return redirect(url_for('login'))
    return render_template('change_password.html',title="Change Password",legend="Change Password",form=form)

@app.route('/survey', methods=['GET', 'POST'])
@login_required
def survey():
    user_id = session.get('user_id')
    if request.method == 'POST':
        
        user_survey = User.query.filter_by(id=user_id).first()

        if user_survey:
            user_survey.fname = request.form['first_name']
            user_survey.lname = request.form['last_name']
            user_survey.email = request.form['email']
            user_survey.age = request.form['age']
            user_survey.gender = request.form.get('gender')
            #user_survey.other_gender = request.form.get('other_gender', '')
            user_survey.race = request.form.get('race')
            #user_survey.other_race = request.form.get('other_race', '')
            user_survey.religion = request.form.get('religion')
            #user_survey.other_religon = request.form.get('other_religion')
            user_survey.education = request.form.get('education')

            db.session.commit()
            return redirect(url_for('survey2'))
    return render_template('survey.html')


    
@app.route('/survey2', methods=['GET', 'POST'])
@login_required
def survey2():
    user_id = session.get('user_id')
    if request.method == 'POST':
        user_survey = User.query.filter_by(id=user_id).first()
        user_survey.pronoun_pref = request.form.get('gender_pref')
        #user_survey.pronoun_pref = request.form.get('other_race_text')
        user_survey.age_range_min = request.form.get('minAge')
        user_survey.age_range_max = request.form.get('maxAge')
        race = request.form.getlist('race')
        religion = request.form.getlist('rel')
        #other_selected_race = request.form.get('other_race_text')
        user_survey.race_pref = json.dumps(race)
        user_survey.religion_pref = json.dumps(religion)

        db.session.commit()
        return redirect(url_for('survey3'))
    return render_template('survey2.html')

@app.route('/survey3', methods=['GET', 'POST'])
@login_required
def survey3():
    user_id = session.get('user_id')
    if request.method == 'POST':
        user_survey = User.query.filter_by(id=user_id).first()
        user_survey.occupation = request.form.get('occupation')
        user_survey.occupation_pref = request.form.get('occupation_list')
        user_survey.hobbies = request.form.get('hobbies')
        user_survey.personality = request.form.get('personality')
        user_survey.long_term = request.form.get('goals')
        db.session.commit()
        return redirect(url_for('survey4'))
    return render_template('survey3.html')

@app.route('/survey4', methods=['GET', 'POST'])
@login_required
def survey4():
    #mark survey as completed
    user_id = session.get('user_id')
    if request.method == 'POST':
        user_survey = User.query.filter_by(id=user_id).first()
        user_survey.interaction = request.form.get('Interaction_pref')
        virtual_dating = request.form.get('Virtual')
        if virtual_dating == "True":
            user_survey.virtual = True
        else:
            user_survey.virtual = False

        safty = request.form.get('Safety')
        if safty == "True":
            user_survey.social = True
        else:
            user_survey.social = False

        user_survey.completed_survey = True
        db.session.commit()

        if user_survey.completed_survey == True:
            return render_template('dashboard.html')
        else:
            return redirect(url_for('survey'))
    return render_template('survey4.html')

#Once the use is logged in, they go to the logged in dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    #if user is new, redirect to survey
    if current_user.completed_survey == False:
        return redirect(url_for('survey'))
    else:
        return render_template('dashboard.html')

#Page where the user can edit their profile
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateForm()
    image = url_for('static', filename='pics/profile/' + current_user.profile_pic)
    return render_template('account.html', form=form, image_file = image)

#edit the user's profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UpdateForm()
    if form.validate_on_submit():
        #update the user's info
        current_user.username = form.username.data
        current_user.profile_pic = form.profile_pic.data
        current_user.email = form.email.data
        current_user.fname = form.fname.data
        current_user.lname = form.lname.data
        current_user.bio = form.bio.data
        # Grab Image Name
        pic_filename = secure_filename(current_user.profile_pic.filename)
        # Set UUID
        pic_name = str(uuid.uuid1()) + "_" + pic_filename
        # Save That Image
        saver = form.profile_pic.data
        current_user.profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
        current_user.profile_pic = pic_name
        db.session.commit()
        current_user.profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
        return redirect(url_for('dashboard'))
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
    #flash('You have successfully logged out.')
    return redirect(url_for('login'))

#This is the Signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        #creates hashed password to encrypt it
        hashed_password= bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,password=hashed_password,lname=
                        form.lname.data,fname=form.fname.data,email=form.email.data, phone_number=form.phone_number.data)
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

@app.route('/video3')
def video3():
    return render_template('video3.html')

@app.route('/video4')
def video4():
    return render_template('video4.html')

@app.route('/video5')
def video5():
    return render_template('video5.html')

@app.route('/video6')
def video6():
    return render_template('video6.html')

@app.route('/video7')
def video7():
    return render_template('video7.html')

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
        filename1 = "data/" + str(id1) + "_" + str(i) + ".pkl"
        filename2 = "data/" + str(id2) + "_" + str(i) + ".pkl"

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

    #one of them is empty
    if not thang1 or not thang2:
        return -1

    #parse the data or some shid
    #there are four different types of brainwaves so we need to compare each one
    #delta, theta, alpha, beta

    #FIRST get all brainbit objects into one list
    all1 = [thang for sublist in thang1 for thang in sublist]
    all2 = [thang for sublist in thang2 for thang in sublist]

    #see the data
    print("all1: ", all1, " all2: ", all2)

    #for each brainwave
    for i in range(len(all1)):
        #I guess we can compare one by one and add it to the avgs
        #while both index's exist
        if all1[i] is None or all2[i] is None:
            if i == 0:
                return -1
            else:
                return avgs

        ###HERE is where we need to parse the data so we can make a numpy array: np.array([0, 0])
        #THIS MIGHT WORK?!
        o1 = all1[i][0].O1 - all2[i][0].O1
        o2 = all1[i][0].O2 - all2[i][0].O2
        t3 = all1[i][0].T3 - all2[i][0].T3
        t4 = all1[i][0].T4 - all2[i][0].T4  
        array1 = np.array([o1, o2])
        array2 = np.array([t3, t4])

        print("array1: ", array1, " array2: ", array2)

        avgs += np.sqrt(np.sum((array1 - array2)**2))
        count += 1

    return (avgs / count)

@app.route('/send_sms/<int:user_id>', methods=['POST'])
@login_required
def send_sms(user_id):
    user = User.query.filter_by(id=user_id).first()
    phone_number = '+1' + user.phone_number
    message = request.form['text-input']  # Retrieve the message from the form

    print("sending sms to: ", phone_number, " with message: ", message)

    # Send the SMS using Twilio
    #message = client.messages.create(
        #to=phone_number,
        #from_=twilio_number,
        #body=message
    #)

    return 'SMS sent with SID: ' + message.sid

if __name__ == '__main__':
    db.create_all()
    db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=80)
    #socketio.run(app, debug=True, host='0.0.0.0', port=80, allow_unsafe_werkzeug=True)