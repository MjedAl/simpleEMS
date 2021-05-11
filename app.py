# Python standard libraries
import json
import os
import functools
from datetime import datetime
# Third-party libraries
from flask import Flask, redirect, request, url_for, flash, render_template, abort
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_migrate import current
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from oauthlib.oauth2 import WebApplicationClient
import requests
# Internal imports
from db import setup_db, User, Event, UsersEvents

try:
    from secret import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, FLASK_SECRET_KEY
except ModuleNotFoundError:
    GOOGLE_CLIENT_ID = None
    GOOGLE_CLIENT_SECRET = None
    FLASK_SECRET_KEY = None

# Configuration
GOOGLE_CLIENT_ID = os.environ.get(
    "GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID)
GOOGLE_CLIENT_SECRET = os.environ.get(
    "GOOGLE_CLIENT_SECRET", GOOGLE_CLIENT_SECRET)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Flask app setup
app = Flask(__name__)
app.secret_key = (os.environ.get("SECRET_KEY")
                  or FLASK_SECRET_KEY) or os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)
setup_db(app)

# upload setup
UPLOAD_FOLDER = './static/uploads'
ALLOWED_PICTURES_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4 MB max image size
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


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


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated():
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
        if current_user.is_authenticated():
            flash('Logged in', 'success')
            return redirect(url_for("index"))
        else:
            return render_template('register.html')
    else:
        f_name = request.form['first_name']
        l_name = request.form['last_name']
        password = request.form['password']
        password_repeat = request.form['password_repeat']
        email = request.form['email']

        if password == password_repeat:
            user = User.getByEmail(email)
            if user is None:
                myUser = User(
                    name=f_name+' '+l_name, email=email, signedWithGoogle=False
                )
                myUser.generate_my_password_hash(password)
                myUser.insert()
                login_user(myUser, remember=True)
                flash('Account created', 'success')
                return redirect(url_for("index"))
            else:
                flash('Email is taken by another user. Please try again!', 'danger')
                return redirect(request.url)
        else:
            flash('Passwords don\'t match!', 'danger')
            return redirect(request.url)


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
                id=unique_id, name=users_name, email=users_email, picture=picture, signedWithGoogle=True
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
                    filename = secure_filename(picture.filename)
                    pictureLocation = event.id + os.path.splitext(filename)[1]
                    picture.save(os.path.join(
                        app.config['UPLOAD_FOLDER'], pictureLocation))
                    event.updatePicture(pictureLocation)

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
            if current_user.is_authenticated():
                if event.owner_id != current_user.id:
                    abort(403)
            else:
                abort(403)
        users_events = None
        if current_user.is_authenticated():
            if event.owner_id == current_user.id:
                users_events = UsersEvents.query.filter_by(
                    event_id=event.id).all()
        return render_template('event.html', event=event, currentUser=current_user, users_events=users_events)


@ app.route('/event/<id>/subscribe', methods=['GET'])
def eventSub(id):
    if not current_user.is_authenticated():
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
        event.removeUser(current_user)
        return redirect(url_for("eventsG"))


@ app.route('/events', methods=['GET'])
def eventsG():
    # events = Event.query.filter_by(
    #     private=False).order_by(Event.time).all()
    events = Event.query.filter(Event.time > datetime.now()).filter_by(
        private=False).order_by(Event.time).all()
    if current_user.is_authenticated():
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


if __name__ == "__main__":
    # app.run(ssl_context="adhoc")
    # app.run(use_reloader=True, debug=True, host='0.0.0.0')
    app.run(debug=True)
