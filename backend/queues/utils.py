import requests

def check_queue(user_id, session_id):
    sessions = Session.query.filter_by(session_id=session_id)
    counter = 1
    for session in sessions:
        if user_id == session.user_id:
            return counter
        else:
            count += 1
    return -1