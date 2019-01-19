from flask import Blueprint, request
from backend.models import User, Session
from backend import db, bcrypt
import json

stats = Blueprint('stats', __name__)


@stats.route('/stats/individual/users_helped')
def users_helped_i():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        helper_id = request_json['helper_id']
        helper = User.query.filter_by(id=helper_id).first()
        help_sessions = Session.query.filter_by(helper_id=helper_id)
        num_success_sessions = len(help_sessions)
        return json.dumps({'status': 1, 'name': helper.name, 'email': helper.email,
                           'num_sessions': num_success_sessions})


@stats.route('/stats/individual/help_requested')
def users_help_requested_i():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        requester_id = request_json['requester_id']
        requester = User.query.filter_by(id=requester_id).first()
        help_sessions = Session.query.filter_by(requester_id=requester_id)
        num_help_sessions = len(help_sessions)
        return json.dumps({'status': 1, 'name': requester.name, 'email': requester.email,
                           'num_sessions': num_help_sessions})


@stats.route('/stats/group/users_helped')
def users_helped_t():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        help_sessions = Session.query.all
        num_help_sessions = len(help_sessions)
        return json.dumps({'status': 1, 'num_sessions': num_help_sessions})


@stats.route('/stats/group/dropped_sessions')
def dropped_sessions_t():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        help_sessions = Session.query.filter_by(help_status=2)
        num_help_sessions = len(help_sessions)
        return json.dumps({'status': 1, 'num_sessions': num_help_sessions})

@stats.route('/stats/individual/dropped_sessions')
def dropped_sessions_i():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        requester_id = request_json['requester_id']
        requester = User.query.filter_by(id=requester_id).first()
        help_sessions = Session.query.filter_by(help_status=2)
        num_help_sessions = len(help_sessions)
        return json.dumps({'status': 1, 'num_sessions': num_help_sessions})