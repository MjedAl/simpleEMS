import os
from os import abort
from flask import Blueprint, session, jsonify, request, render_template, current_app
from flask_jwt_extended.internal_utils import user_lookup
from flask_jwt_extended.utils import create_refresh_token
from db import User, Event, UsersEvents
from datetime import datetime
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required, current_user)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import boto3
import base64

app_api_v1 = Blueprint('app_api_v1', __name__)

mail = Mail()
s3_client = boto3.client('s3', aws_access_key_id=os.environ.get("aws_access_key"),
                         aws_secret_access_key=os.environ.get("aws_secret_key"))


def generate_email_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])


@app_api_v1.route("/api/v1/events", methods=['GET'])
@jwt_required(optional=True)
def getEvents():
    try:
        events = Event.query.filter_by(
            private=False).order_by(Event.time).all()
        # events = Event.query.filter(Event.time > datetime.now()).filter_by(
        #     private=False).order_by(Event.time).all()
        if current_user:
            return jsonify({
                'success': True,
                'events': [event.shortUser(current_user) for event in events],
            })
        return jsonify({
            'success': True,
            'events': [event.short() for event in events]
        })
    except Exception as e:
        return error_500()


@app_api_v1.route("/api/v1/events", methods=['POST'])
@jwt_required()
def postEvent():
    try:
        JSON_body = request.get_json()
        if JSON_body is None:
            return jsonify({
                'success': False,
                'message': 'invalid request missing body'
            }), 400
        name = JSON_body.get('name')
        description = JSON_body.get('description')
        location = JSON_body.get('location')
        date = JSON_body.get('date')
        if not name or not description or not date or not location:
            return jsonify({
                'success': False,
                'message': 'invalid request missing params'
            }), 400
        else:
            try:
                date_time_obj = datetime.strptime(
                    date, '%Y-%m-%d %H:%M:%S.%fZ')
            except Exception:
                return jsonify({
                    'success': False,
                    'message': 'Couldn\'t parse time'
                }), 400
            event = Event(owner_id=current_user.id, name=name, description=description,
                          location=location, time=date_time_obj)
            event.insert()
            image = JSON_body.get('image')
            if image:
                imageName = event.id+'.png'
                s3_client.put_object(Body=base64.b64decode(image),
                                     Bucket='flask-images',
                                     Key='simpleEMS/'+imageName,
                                     ContentType=request.mimetype)
                imageURL = 'https://flask-images.s3.eu-central-1.amazonaws.com/simpleEMS/' + imageName
                event.updatePicture(imageURL)
        return jsonify({
            'success': True,
            'event_id': event.id
        })
    except Exception as e:
        return error_500()


@app_api_v1.route("/api/v1/passwordReset", methods=['POST'])
def forgotPassword():
    try:
        JSON_body = request.get_json()
        if JSON_body is None:
            return jsonify({
                'success': False,
                'message': 'invalid request'
            }), 400
        email = JSON_body.get("email")
        if email is not None:
            user = User.getByEmail(email)
            if user is not None:
                token = generate_email_token(email)
                msg = Message(
                    'SimpleEMS - Password reset', sender='simpleEMS <'+current_app.config['MAIL_USERNAME']+'>', recipients=[email])
                msg.html = render_template(
                    '/emails/reset_password.html', link=request.host_url+'reset/'+token)
                mail.send(msg)
        return jsonify({
            'success': True,
            'message': "Email will be sent if user with email is found"
        }), 200
    except Exception as e:
        return error_500()


@app_api_v1.route("/api/v1/myEvents", methods=['GET'])
@jwt_required()
def getMyEvents():
    try:
        subbedEvents = UsersEvents.query.filter_by(
            user_id=current_user.id).all()
        return jsonify({
            "success": True,
            "SubbedEvents": [subbedEvent.eventInfo() for subbedEvent in subbedEvents]
        })
    except Exception as e:
        return error_500()


@app_api_v1.route("/api/v1/events/<event_id>", methods=['GET'])
@jwt_required(optional=True)
def getEvent(event_id):
    try:
        if id is None:
            return error_404()
        event = Event.query.filter_by(id=str(event_id)).first()
        if event is None:
            return error_404()
        subbedUsersInfo = 'Private'
        if current_user is not None:
            # only owner can view the subbed users
            if current_user.id == event.owner_id:
                usersEvent = UsersEvents.query.filter_by(
                    event_id=event.id).all()
                subbedUsersInfo = [userEvent.userInfo()
                                   for userEvent in usersEvent]
        if event.private:
            if current_user is None:
                error_401()
            else:
                if current_user.id == event.owner_id or (current_user in event.users):
                    return jsonify({
                        'success': True,
                        'event': event.short(),
                        'subbedUsersInfo': subbedUsersInfo
                    })
                else:
                    error_401()
        return jsonify({
            'success': True,
            'event': event.short(),
            'subbedUsersInfo': subbedUsersInfo
        })
    except Exception as e:
        return error_500()


@app_api_v1.route('/api/v1/events/<event_id>/subscribe', methods=['POST'])
@jwt_required()
def subscribeEvent(event_id):
    try:
        if event_id is None:
            error_400()
        event = Event.query.filter_by(id=str(event_id)).first()
        if event is None:
            error_404()
        # TODO add logic to subscribe to private events
        if event.private and event.owner_id != current_user.id:
            error_401()
        event.addUser(current_user)
        return jsonify({
            'success': True
        }), 200
    except Exception as e:
        return error_500()


@app_api_v1.route('/api/v1/events/<event_id>/unsubscribe', methods=['POST'])
@jwt_required()
def unsubscribeEvent(event_id):
    try:
        if event_id is None:
            error_400()
        event = Event.query.filter_by(id=str(event_id)).first()
        if event is None:
            error_404()
        # TODO add logic to subscribe to private events
        if event.private and event.owner_id != current_user.id:
            error_401()
        event.removeUser(current_user)
        return jsonify({
            'success': True
        }), 200
    except Exception as e:
        return error_500()


@app_api_v1.route('/api/v1/login', methods=['POST'])
def apiLogin():
    try:
        JSON_body = request.get_json()
        if JSON_body is None:
            return jsonify({
                'success': False,
                'message': 'invalid request'
            }), 400
        email = JSON_body.get("email")
        password = JSON_body.get("password")
        if email is not None and password is not None:
            user = User.getByEmailAndPassword(email, password)
            if user is None:
                return jsonify({
                    'success': False,
                    'message': 'invalid user or password'
                }), 401
            else:
                return jsonify({
                    'success': True,
                    'token': create_access_token(identity=user, fresh=True),
                    'refresh_token': create_refresh_token(identity=user),
                    'userData': user.short(),
                }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Missing email or password'
            }), 400
    except Exception as e:
        return error_500()


@app_api_v1.route('/api/v1/register', methods=['POST'])
def apiRegister():
    try:
        JSON_body = request.get_json()
        if JSON_body is None:
            return jsonify({
                'success': False,
                'message': 'invalid request'
            }), 400
        name = JSON_body.get("name")
        email = JSON_body.get("email")
        password = JSON_body.get("password")
        if email is not None and password is not None and name is not None:
            user = User.getByEmail(email)
            if user is None:
                user = User(
                    name=name, email=email
                )
                user.generate_my_password_hash(password)
                user.insert()
                token = generate_email_token(user.email)
                msg = Message(
                    'SimpleEMS - Registration', sender='simpleEMS <'+current_app.config['MAIL_USERNAME']+'>', recipients=[user.email])
                msg.html = render_template(
                    '/emails/register_confirm.html', register=True, name=user.name, link=request.host_url+'confirm/'+token)
                mail.send(msg)
                return jsonify({
                    'success': True,
                    'token': create_access_token(identity=user, fresh=True),
                    'refresh_token': create_refresh_token(identity=user),
                    'userData': user.short(),
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'message': 'Account found with the same email'
                }), 401
        else:
            return jsonify({
                'success': False,
                'message': 'Missing params'
            }), 400
    except Exception as e:
        return error_500()


@app_api_v1.route("/api/v1/token", methods=["GET"])
@jwt_required(refresh=True)
def refresh():
    refresh_token = create_access_token(identity=current_user, fresh=False)
    return jsonify({
        'success': True,
        'refreshed_token': refresh_token
    }), 200


@app_api_v1.route("/api/v1/whoAmI", methods=["GET"])
@jwt_required()
def whoAmI():
    return jsonify({
        'success': True,
        'user': current_user.short(),
    }), 200


def error_400():
    return jsonify({
        "success": False,
        "error": 400,
        "message": "Bad request"
    }), 400


def error_404():
    return jsonify({
        "success": False,
        "error": 404,
        "message": "Not found"
    }), 404


def error_401():
    return jsonify({
        "success": False,
        "error": 401,
        "message": "Not authorized"
    }), 401


def error_422():
    return jsonify({
        "success": False,
        "error": 422,
        "message": "Un-processable Entity"
    }), 422


def error_500():
    return jsonify({
        "success": False,
        "error": 500,
        "message": "Internal Server Error"
    }), 500
