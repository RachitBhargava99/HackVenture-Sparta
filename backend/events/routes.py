from flask import Blueprint, request
from backend.models import User, Event
from backend import db
import json

events = Blueprint('queues', __name__)


@events.route('/event/add', methods=['GET', 'POST'])
def add_event():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        lat = request_json['gps'][0]
        lon = request_json['gps'][1]
        user_id = user.id
        new_event = Event(lat=lat, lon=lon, user_id=user_id)
        db.session.add(new_event)
        db.session.commit()
        return json.dumps({'status': 1})


@events.route('/event/modify', methods=['GET', 'POST'])
def modify_event():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        type = request_json['type']
        curr_event = Event.query.filter_by(id=request_json['id'])
        curr_event.type = type
        db.session.commit()
        return json.dumps({'status': 1})


@events.route('/event/get', methods=['GET', 'POST'])
def get_unlogged_events():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        id = user.id
        event_ids = [x.id for x in Event.query.filter_by(user_id=id, type=-1)]
        return json.dumps({'status': 1, 'events': event_ids})
