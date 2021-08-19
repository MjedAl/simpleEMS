import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json
from random import randint
from datetime import datetime
import random
import string

from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

DATABASE_URL = os.environ.get("DATABASE_URL").replace(
    'postgres://', 'postgresql://')
db = SQLAlchemy()


def setup_db(app, admin, myAdminView, UsersView):
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.app = app
    db.init_app(app)
    Migrate(app, db)
    db.create_all()
    app.db = db
    admin.add_view(UsersView(User, db.session))
    admin.add_view(myAdminView(Event, db.session))
    admin.add_view(myAdminView(UsersEvents, db.session))


def random_user_id():
    min_ = 100
    max_ = 1000000000
    rand = randint(min_, max_)
    strId = str(rand)
    while User.query.filter_by(id=strId).first() is not None:
        rand = str(randint(min_, max_))
    return str(rand)


def random_event_id():
    code = "".join([random.choice(string.ascii_letters + string.digits)
                    for n in range(5)])
    while Event.query.filter_by(id=code).first() is not None:
        code = "".join(
            [random.choice(string.ascii_letters + string.digits) for n in range(5)])
    return code


class UsersEvents(db.Model):
    __tablename__ = 'users_events'
    user_id = db.Column(db.String(), db.ForeignKey(
        'user.id'), primary_key=True)
    event_id = db.Column(db.String(), db.ForeignKey(
        'event.id'), primary_key=True)
    addedOn = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="events")
    event = db.relationship("Event", back_populates="users")

    #
    def short(self):
        return {
            "user_id": self.user_id,
            "event_id": self.event_id,
            "user": self.user.short(),
            "event": self.event.short()
        }

    def eventInfo(self):
        return self.event.shortUser(self.user)

    def userInfo(self):
        return {
            "user": self.user.short(),
            "addedOn": self.addedOn
        }

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.String(), primary_key=True,
                   default=random_user_id)
    email = db.Column(db.String(255), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False)
    emailConfirmed = db.Column(db.Boolean(), default=False)
    picture = db.Column(db.String())
    password = db.Column(db.String())
    signedWithGoogle = db.Column(db.Boolean(), default=False)
    roles = db.Column(db.ARRAY(db.String()), default={})
    # events user subscribed to
    events = db.relationship("UsersEvents", back_populates="user")
    # events the user has created
    createdEvents = db.relationship('Event')

    def short(self):
        return {
            "name": self.name,
            "id": self.id,
            "email": self.email,
            "emailConfirmed": self.emailConfirmed,
            "picture": self.picture
        }

    def generate_my_password_hash(self, pwd):
        self.password = generate_password_hash(pwd)

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def __repr__(self):
        return json.dumps(self.short())

    def verify_password(self, pwd):
        return check_password_hash(self.password, pwd)

    @staticmethod
    def get(user_id):
        return User.query.filter_by(id=user_id).first()

    @staticmethod
    def getByEmail(email):
        email = email.lower()
        return User.query.filter_by(email=email).first()

    @staticmethod
    def getByEmailAndPassword(email, password):
        user = User.getByEmail(email)
        if user is None:
            return None
        else:
            if user.signedWithGoogle:  # users from Google shouldn't sign in using email and password method
                return None
            if user.verify_password(password):
                return user
            else:
                return None


class Event(db.Model):
    __tablename__ = 'event'
    id = db.Column(db.String(), primary_key=True, default=random_event_id)
    location = db.Column(db.String())
    name = db.Column(db.String(), nullable=False)
    description = db.Column(db.String())
    owner_id = db.Column(db.String(), db.ForeignKey('user.id'))
    owner = db.relationship('User', back_populates="createdEvents")

    picture = db.Column(db.String())
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    maxUsers = db.Column(db.Integer(), default=-1)
    currentRegistered = db.Column(db.Integer(), default=0)
    private = db.Column(db.Boolean(), default=False)

    users = db.relationship(
        "UsersEvents", back_populates="event")

    # read this doc if you forgot why/how you did this :)
    # https://docs.sqlalchemy.org/en/14/orm/basic_relationships.html#association-object

    def addUser(self, user):
        usersEvent = UsersEvents()
        usersEvent.user = user
        usersEvent.event = self
        self.currentRegistered = self.currentRegistered + 1
        self.users.append(usersEvent)
        self.update()

    def removeUser(self, user):
        self.currentRegistered = self.currentRegistered - 1
        userEvent = UsersEvents.query.filter_by(
            user_id=user.id, event_id=self.id).first()
        userEvent.delete()
        self.update()

    def updatePicture(self, picture):
        self.picture = picture
        self.update()

    def short(self):
        return {
            "id": self.id,
            "location": self.location,
            "name": self.name,
            "description": self.description,
            "time-full": self.time.strftime("%Y-%m-%d %H:%M:%S.%fZ"),
            "time-day": self.time.strftime("%d"),
            "time-month": self.time.strftime("%b"),
            "time-time": self.time.strftime("%H:%M %p"),
            "currentRegistered": self.currentRegistered,
            "ownerName": self.owner.name,
            "image": self.getPicture(),
            "private": self.private
        }

    def shortUser(self, user):
        return {
            "id": self.id,
            "location": self.location,
            "name": self.name,
            "description": self.description,
            "time-full": self.time.strftime("%Y-%m-%d %H:%M:%S.%fZ"),
            "currentRegistered": self.currentRegistered,
            "ownerName": self.owner.name,
            "private": self.private,
            "image": self.getPicture(),
            "registered": getattr(UsersEvents.query.filter_by(
                user_id=user.id, event_id=self.id).first(), 'addedOn', 'False')
        }

    def getPicture(self):
        if self.picture is None or self.picture == '':
            return None
        # TODO check if image is stored locally or in AWS S3
        # if (self.picture.startswith('http')):
        return self.picture
        # return 'http://192.168.1.102:5000/static/uploads/'+self.picture

    def timeDetails(self):
        return {
            "time-day": self.time.strftime("%d"),
            "time-month": self.time.strftime("%b"),
            "time-time": self.time.strftime("%H:%M %p")
        }

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def __repr__(self):
        return json.dumps(self.short())
