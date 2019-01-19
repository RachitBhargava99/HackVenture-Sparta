from flask import Blueprint, request
from backend.models import User, Session
from backend import db
import json
from backend.queues.utils import check_queue

queues = Blueprint('queues', __name__)


@queues.route('/queue/enter', methods=['GET', 'POST'])
def enter_queue():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    elif Session.query.filter_by(requesterID=user.id, help_status=0).first():
        return json.dumps({'status': 0,
                           'error': "Sorry, you are already in a queue."})
    company_id = request_json['company_id']
    new_session = Session(requesterID=user.id, companyID=company_id)
    db.session.add(new_session)
    db.session.commit()
    return json.dumps({'status': 1})


@queues.route('/queue/exit', methods=['GET', 'POST'])
def exit_queue():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    elif Session.query.filter_by(requesterID=user.id, help_status=0).first() is None:
        return json.dumps({'status': 0,
                           'error': "Sorry, you are not in any queue at the moment."})
    current_session = Session.query.filter_by(requesterID=user.id, help_status=0).first()
    current_session.help_status = 2
    db.session.commit()
    return json.dumps({'status': 1})


@queues.route('/queues/modify/helped', methods=['GET', 'POST'])
def queue_student_helped():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        session = Session.query.filter_by(helperID=user.id, help_status=4).first()
        session.help_status = 1
        session.assigned_status = False
        session.helperID = user.id
        db.session.commit()
        return json.dumps({'status': 1})


@queues.route('/queues/not_found', methods=['GET', 'POST'])
def queue_user_not_found():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        session = Session.query.filter_by(helperID=user.id, help_status=4).first()
        session.help_status = 2
        session.helperID = -1
        session.assigned_status = False
        db.session.commit()
        return json.dumps({'status': 1})


@queues.route('/queues/status', methods=['GET', 'POST'])
def queue_status():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        session_id = request.get_json()
        queue_num = check_queue(user.id, session_id)
        if queue_num == -1:
            return json.dumps({'status': 1, 'existence': 0})
        else:
            return json.dumps({'status': 1, 'existence': 1, 'queue_num': queue_num})


@queues.route('/queues/next', methods=['GET', 'POST'])
def queue_next():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        session = Session.query.filter_by(help_status=0, assigned_status=False).first()
        session.assigned_status = True
        db.session.commit()
        user = User.query.filter_by(user_id=session.user_id).first()
        return json.dumps({'status': 1, 'student_name': user.name})


@queues.route('/queues/users/get_session_data', methods=['GET', 'POST'])
def get_session_data_u():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        sessions = Session.query.filter_by(requesterID=user.id, help_status=1)
        final = {"rows": []}
        count = 1
        for session in sessions:
            final["rows"].append({
                "id": count,
                "date": session.timestamp.strftime("%b %d, %Y  %I:%M %p"),
                "topic": session.topic,
                "helper": User.query.filter_by(id=session.helperID).first().name
            })
            count += 1
        return json.dumps({'status': 1, 'data': final["rows"]})


@queues.route('/queues/admin/get_session_data', methods=['GET', 'POST'])
def get_session_data_a():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        sessions = Session.query.filter_by(helperID=user.id, help_status=1)
        final = {"rows": []}
        count = 1
        for session in sessions:
            final["rows"].append({
                "id": count,
                "date": session.timestamp.strftime("%b %d, %Y  %I:%M %p"),
                "topic": session.topic,
                "requester": User.query.filter_by(id=session.requesterID).first().name
            })
            count += 1
        return json.dumps({'status': 1, 'data': final["rows"]})


@queues.route('/queues/master/get_session_data', methods=['GET', 'POST'])
def get_session_data_m():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        sessions = Session.query.filter_by(help_status=1)
        final = {"rows": []}
        count = 1
        for session in sessions:
            final["rows"].append({
                "id": count,
                "date": session.timestamp.strftime("%b %d, %Y  %I:%M %p"),
                "topic": session.topic,
                "helper": User.query.filter_by(id=session.helperID).first().name,
                "requester": User.query.filter_by(id=session.requesterID).first().name
            })
            count += 1
        return json.dumps({'status': 1, 'data': final["rows"]})
