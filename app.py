# Python standard libraries
import json
import os
import functools
from datetime import datetime
# Third-party libraries
import boto3
from flask import Flask, redirect, request, url_for, flash, render_template, abort
from flask.templating import Environment
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_migrate import current
from jinja2 import environment
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from itsdangerous import URLSafeTimedSerializer
from oauthlib.oauth2 import WebApplicationClient
import requests
from flask_mail import Mail, Message
# Internal imports
from db import setup_db, User, Event, UsersEvents

if not os.environ.get("PRODUCTION"):
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv())


GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration")
# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)
setup_db(app)
# Email setup
app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.environ.get("MAIL_PORT"))
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("FLASK_SALT")
mail = Mail(app)

# upload setup
UPLOAD_FOLDER = './static/uploads'
ALLOWED_PICTURES_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4 MB max image size
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # TODO replace on production
# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

s3_client = boto3.client('s3', aws_access_key_id=os.environ.get("aws_access_key"),
                         aws_secret_access_key=os.environ.get("aws_secret_key"))


def generate_email_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return None
    return email


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def roles_required(*role_names):
    def decorator(original_route):
        @functools.wraps(original_route)
        def decorated_route(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            for role in role_names:
                if role not in current_user.roles:
                    abort(403)
            return original_route(*args, **kwargs)
        return decorated_route
    return decorator


@app.route("/")
def index():
    return render_template('index.html', currentUser=current_user)


@app.route("/reset", methods=['GET', 'POST'])
def password_reset():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        return render_template('reset.html')
    else:
        email = request.form["email"]
        if email is None:
            flash('Invalid email!', 'danger')
            return render_template('reset.html')
        else:
            user = User.query.filter_by(
                email=email, signedWithGoogle=False).one_or_none()
            if user is not None:
                token = generate_email_token(email)
                msg = Message(
                    'SimpleEMS - Password reset', sender='simpleEMS <'+app.config['MAIL_USERNAME']+'>', recipients=[email])
                msg.html = render_template(
                    '/emails/reset_password.html', link=request.host_url+'reset/'+token)
                mail.send(msg)
            flash('Email will be sent if user with email is found', 'success')
            return render_template('reset.html')


@app.route("/reset/<token>", methods=['POST', 'GET'])
def password_reset_token(token):
    if request.method == 'GET':
        return render_template('new_password.html', token=token)
    else:
        password = request.form['password']
        formToken = request.form['token']
        # password reset token should expire with in 15m
        if password is not None and formToken is not None:
            email = confirm_token(formToken, 900)
            if email is None:
                flash('The reset link is invalid or has expired.', 'danger')
                return render_template('new_password.html')
            user = User.query.filter_by(email=email).first()
            user.generate_my_password_hash(password)
            user.update()
            flash('Password changed, Please log in', 'success')
            return redirect(url_for("login"))
        flash('Invalid operation!', 'danger')
        return render_template('new_password.html')


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            flash('Logged in', 'success')
            return redirect(url_for("index"))
        else:
            return render_template('login.html')
    else:
        email = request.form["email"]
        password = request.form["password"]
        if email is not None and password is not None:
            user = User.getByEmailAndPassword(email, password)
            if user is None:
                flash('Invalid email or password. Please try again!', 'danger')
                return render_template('login.html')
            else:
                login_user(user, remember=True)
                flash('Logged in', 'success')
                return redirect(url_for("index"))


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if current_user.is_authenticated:
            flash('Logged in', 'success')
            return redirect(url_for("index"))
        else:
            return render_template('register.html')
    else:
        f_name = request.form['first_name']
        l_name = request.form['last_name']
        password = request.form['password']
        # password_repeat = request.form['password_repeat']
        email = request.form['email']

        # if password == password_repeat:
        user = User.getByEmail(email)
        if user is None:
            myUser = User(
                name=f_name+' '+l_name, email=email, signedWithGoogle=False
            )
            myUser.generate_my_password_hash(password)
            myUser.insert()
            login_user(myUser, remember=True)
            # Send confirmation email
            token = generate_email_token(current_user.email)
            msg = Message(
                'SimpleEMS - Registration', sender='simpleEMS <'+app.config['MAIL_USERNAME']+'>', recipients=[current_user.email])
            msg.html = render_template(
                '/emails/register_confirm.html', register=True, name=current_user.name, link=request.host_url+'confirm/'+token)
            mail.send(msg)

            flash('Account created', 'success')
            return redirect(url_for("index"))
        else:
            flash('Email is taken by another user. Please try again!', 'danger')
            return redirect(request.url)
        # else:
        #     flash('Passwords don\'t match!', 'danger')
        #     return redirect(request.url)


@app.route('/confirm', defaults={'token': None})
@app.route('/confirm/<token>')
def confirmEmail(token):
    if current_user.is_authenticated:
        if current_user.emailConfirmed:
            flash('Your email is already confirmed', 'success')
            return redirect(url_for("index"))
    if token is None:
        # send the confirmation email
        token = generate_email_token(current_user.email)
        msg = Message(
            'SimpleEMS - Registration', sender='simpleEMS <'+app.config['MAIL_USERNAME']+'>', recipients=[current_user.email])
        msg.html = render_template(
            '/emails/register_confirm.html', name=current_user.name, link=request.host_url+'confirm/'+token)
        mail.send(msg)
        flash('Confirmation email has been sent!', 'success')
        return redirect(url_for("index"))
    else:
        email = confirm_token(token)
        if email is None:
            flash('The confirmation link is invalid or has expired.', 'danger')
            return redirect(url_for("index"))
        user = User.query.filter_by(email=email).first()
        user.emailConfirmed = True
        user.update()
        flash('Your email has been confirmed', 'success')
        return redirect(url_for("index"))


@app.route('/gAuth')
def gLogin():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/gAuth/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))
    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["name"]
        getUser = User.get(unique_id)
        if getUser is None:
            getUser = User(
                id=unique_id, name=users_name, email=users_email, picture=picture, signedWithGoogle=True, emailConfirmed=True
            )
            getUser.insert()
        login_user(getUser, remember=True)
        flash('Logged in', 'success')
        return redirect(url_for("index"))
    else:
        return "User email not available or not verified by Google.", 400

# TODO
# @app.route('/profile')
# @login_required
# def profile():
#     return render_template('profile.html', currentUser=current_user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out', 'success')
    return redirect(url_for("index"))


def allowed_picture(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_PICTURES_EXTENSIONS


@app.route('/events', methods=['POST'])
@login_required
def eventsP():
    try:
        name = request.form['Name']
        description = request.form['Description']
        location = request.form['Location']
        date = request.form['dateAndTime']
        private = False
        if 'private' in request.form:
            private = True

        date_time_obj = datetime.strptime(date, '%m/%d/%Y %H:%M %p')
        event = Event(owner_id=current_user.id, name=name, description=description,
                      location=location, time=date_time_obj, private=private)
        event.insert()
        if 'picture' in request.files:
            picture = request.files['picture']
            if picture.filename != '':
                if picture and allowed_picture(picture.filename):
                    imageName = event.id+'.png'
                    s3_client.put_object(Body=picture,
                                         Bucket='flask-images',
                                         Key='simpleEMS/'+imageName,
                                         ContentType=request.mimetype)
                    imageURL = 'https://flask-images.s3.eu-central-1.amazonaws.com/simpleEMS/' + imageName
                    event.updatePicture(imageURL)

        flash('Event Created', 'success')
        return redirect(url_for("eventG", id=event.id))
    except RequestEntityTooLarge as e:
        flash('Picture size is big!', 'danger')
        return render_template('index.html', currentUser=current_user)


@ app.route('/event/<id>', methods=['GET'])
def eventG(id):
    if id is None:
        return redirect(url_for("eventsG"))
    else:
        event = Event.query.filter_by(id=str(id)).first()
        if event is None:
            abort(404)

        if event.private:
            if current_user.is_authenticated:
                if event.owner_id != current_user.id:
                    abort(403)
            else:
                abort(403)
        users_events = None
        if current_user.is_authenticated:
            if event.owner_id == current_user.id:
                users_events = UsersEvents.query.filter_by(
                    event_id=event.id).all()
        return render_template('event.html', event=event, currentUser=current_user, users_events=users_events)


@ app.route('/event/<id>/subscribe', methods=['GET'])
def eventSub(id):
    if not current_user.is_authenticated:
        flash('Please log in first', 'danger')
        return redirect(url_for("eventsG"))
    if id is None:
        return redirect(url_for("eventsG"))
    else:
        event = Event.query.filter_by(id=str(id)).first()
        if event is None:
            abort(404)
        if event.private and event.owner_id != current_user.id:
            abort(403)
        # Should i msg the owner or not? idk, maybe if the owner wants. TODO ask event owner opinion, change template
        # msg = Message(
        #     'simpleEMS - New subscriber', sender='simpleEMS yourId@gmail.com', recipients=[event.owner.email])
        # msg.body = "New user ("+current_user.email + \
        #     ") has subsribred to your event: "+event.name
        # mail.send(msg)
        event.addUser(current_user)
        return redirect(url_for("eventsG"))


@ app.route('/event/<id>/unsubscribe', methods=['GET'])
@ login_required
def eventUnsub(id):
    if id is None:
        return redirect(url_for("eventsG"))
    else:
        event = Event.query.filter_by(id=str(id)).first()
        if event is None:
            abort(404)
        if event.private and event.owner_id != current_user.id:
            abort(403)
        # Should i msg the owner or not? idk, maybe if the owner wants. TODO ask event owner opinion, change template
        # msg = Message(
        #     'simpleEMS - New unsubscribed', sender='simpleEMS yourId@gmail.com', recipients=[event.owner.email])
        # msg.body = "User ("+current_user.email + \
        #     ") has unsubscribed to your event: "+event.name
        # mail.send(msg)
        event.removeUser(current_user)
        return redirect(url_for("eventsG"))


@ app.route('/events', methods=['GET'])
def eventsG():
    events = Event.query.filter_by(
        private=False).order_by(Event.time).all()
    # events = Event.query.filter(Event.time > datetime.datetime.now()).filter_by(
    #     private=False).order_by(Event.time).all()
    if current_user.is_authenticated:
        subbedEvents = UsersEvents.query.filter_by(
            user_id=current_user.id).all()
        userSubbedEventsIDs = [str(e.event_id) for e in subbedEvents]
        return render_template('events.html', events=events, currentUser=current_user, userSubbedEventsIDs=userSubbedEventsIDs)
    return render_template('events.html', events=events, currentUser=current_user)


@ app.route("/admin")
@ login_required
@ roles_required('admin')
def admin():
    return render_template('admin.html')


@ app.errorhandler(404)
def error404(e):
    return render_template('error.html', error=404), 404


@ app.errorhandler(401)
def error401(e):
    return render_template('error.html', error=401), 401


@ app.errorhandler(403)
def error403(e):
    return render_template('error.html', error=403), 403


@ app.errorhandler(413)
def error413(e):
    flash('Picture size is big!', 'danger')
    return render_template('index.html', currentUser=current_user)


# if __name__ == "__main__":
    #     # app.run(ssl_context="adhoc")
    # app.run(use_reloader=True, debug=True, host='0.0.0.0')
    # app.run(debug=False, host='0.0.0.0')
#     # app.run(debug=True)
