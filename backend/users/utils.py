from backend import mail, db
from flask import url_for
from backend.models import Session, User, CheckInSession, Company
from datetime import datetime, timedelta
from sqlalchemy import and_, or_


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender = 'rachitbhargava99@gmail.com', recipients = [user.email])
    msg.body = f'''To reset your password, kindly visit: {url_for('users.reset', token = token, _external = True)}

Kindly ignore this email if you did not make this request'''
    mail.send(msg)


def get_basic_nums_a(auth_token):
    user = User.verify_auth_token(auth_token)
    queue_sessions = Session.query.filter_by(help_status=0, companyID=user.company_id).count()
    helper_sessions = User.query.filter_by(isActive=True, company_id=user.company_id).count()
    est_wait = queue_sessions * 6 / helper_sessions if helper_sessions != 0 else "No Helper Available"
    current_time = datetime.now()
    time_1_week_back = current_time - timedelta(weeks=1)
    past_24_hours_sessions = Session.query.filter(Session.helperID == user.id,
                                                  Session.timestamp > time_1_week_back,
                                                  Session.help_status == 1)
    num_helper_sessions = past_24_hours_sessions.count()
    return [queue_sessions, helper_sessions, est_wait, num_helper_sessions]


def get_help_info(auth_token):
    user = User.verify_auth_token(auth_token)
    company_id = Session.query.filter_by(requesterID=user.id, help_status=0).first().companyID
    helper_sessions = User.query.filter_by(isActive=True, company_id=company_id).count()
    all_active_sessions = Session.query.filter_by(help_status=0, companyID=company_id)
    queue_pos = 1
    for session in all_active_sessions:
        if session.requesterID == user.id:
            break
        else:
            queue_pos += 1
    est_wait = (queue_pos-1) * 6 / (1 if helper_sessions == 0 else helper_sessions)
    return [helper_sessions, int(est_wait), queue_pos]


def get_help_session_info(auth_token):
    user = User.verify_auth_token(auth_token)
    help_session = Session.query.filter(or_(and_(Session.helperID == user.id, Session.help_status == 3), and_(Session.helperID == user.id, Session.help_status == 4))).first()
    requester = User.query.filter_by(id=help_session.requesterID).first()
    requester_name = requester.name
    return [requester_name]


def get_last_session_info(auth_token, requester_id=0):
    if requester_id == 0:
        user = User.verify_auth_token(auth_token)
    else:
        user = User.query.filter_by(id=requester_id).first()
    last_session = Session.query.filter_by(requesterID=user.id, help_status=1).order_by(Session.id.desc()).first()
    if last_session:
        date = last_session.timestamp
        helper_id = last_session.helperID
        helper = User.query.filter_by(id=helper_id).first()
        helper_name = helper.name
        helper_designation = helper.designation
        helper_company = Company.query.filter_by(id=helper.company_id).first().name
        return [date.strftime("%b %d, %Y  %I:%M %p"), helper_name, helper_designation, helper_company]
    else:
        return ["N/A", "N/A", "N/A", "N/A"]


def get_last_session_info_m(auth_token):
    user = User.verify_auth_token(auth_token)
    last_session = Session.query.filter_by(help_status=1).order_by(Session.id.desc()).first()
    if last_session:
        date = last_session.timestamp
        requester_id = last_session.requesterID
        requester = User.query.filter_by(id=requester_id).first()
        requester_name = requester.name
        helper_id = last_session.helperID
        helper = User.query.filter_by(id=helper_id).first()
        helper_name = helper.name
        company_name = Company.query.filter_by(id=helper.company_id).first().name
        return [date.strftime("%b %d, %Y  %I:%M %p"), requester_name, helper_name, company_name]
    else:
        return ["N/A", "N/A", "N/A", "N/A"]


def get_last_session_info_a(auth_token, helper_id=0):
    if helper_id == 0:
        user = User.verify_auth_token(auth_token)
    else:
        user = User.query.filter_by(id=helper_id).first()
    last_session = Session.query.filter_by(helperID=user.id, help_status=1).order_by(Session.id.desc()).first()
    if last_session:
        date = last_session.timestamp
        requester_id = last_session.requesterID
        requester = User.query.filter_by(id=requester_id).first()
        requester_name = requester.name
        return [date.strftime("%b %d, %Y  %I:%M %p"), requester_name]
    else:
        return ["N/A", "N/A", "N/A"]


def check_helper_session(auth_token):
    user = User.verify_auth_token(auth_token)
    check_in_session = CheckInSession.query.filter_by(userID=user.id, completion=False).first()
    if check_in_session:
        current_time = datetime.now()
        time_1_hour_back = current_time - timedelta(hours=1)
        if check_in_session.timestamp < time_1_hour_back:
            check_in_session.completion = True
            user.isActive = False
            db.session.commit()


def get_remaining_check_in_time(auth_token):
    user = User.verify_auth_token(auth_token)
    check_in_session = CheckInSession.query.filter_by(userID=user.id, completion=False).first()
    current_time = datetime.now()
    time_1_hour_back = current_time - timedelta(hours=1)
    time_diff = (check_in_session.timestamp - time_1_hour_back)
    return time_diff


def get_hourly_info(auth_token):
    user = User.verify_auth_token(auth_token)
    all_sessions = Session.query.all()
    overall_dict = {}
    for i in range(24):
        overall_dict[i] = (0, 0)
    for each in all_sessions:
        if each.help_status == 1:
            overall_dict[each.timestamp.hour] = (overall_dict[each.timestamp.hour][0]+1,
                                                 overall_dict[each.timestamp.hour][1])
        elif each.help_status == 2:
            overall_dict[each.timestamp.hour] = (overall_dict[each.timestamp.hour][0],
                                                 overall_dict[each.timestamp.hour][1]+1)
    return overall_dict


def get_recs_active(auth_token):
    user = User.verify_auth_token(auth_token)
    company_id = user.company_id
    users = [{'name': x.name, 'isActive': x.isActive, 'id': x.id} for x in User.query.filter_by(company_id=company_id)]
    return users


def get_current_sessions(auth_token):
    user = User.verify_auth_token(auth_token)
    company_id = user.company_id
    sessions = [{'id': x.id,
                 'can_name': User.query.filter_by(id=x.requesterID).first().name,
                 'rec_name': User.query.filter_by(id=x.helperID).first().name,
                 'time': (datetime.now() - x.timestamp).total_seconds(),
                 'test': print(x.help_status)}
                for x in Session.query.filter_by(companyID=company_id, help_status=3)]
    return sessions


def db_updater(auth_token):
    user = User.verify_auth_token(auth_token)
    company_id = user.company_id
    company_users = User.query.filter_by(company_id=company_id)
    for each in company_users:
        if each.isActive and Session.query.filter_by(helperID=each.id, help_status=3).first() is None:
            new_session = Session.query.filter_by(help_status=0, companyID=company_id).first()
            if new_session is not None:
                new_session.helperID = each.id
                new_session.help_status = 3
                db.session.commit()


def get_curr_help_info(auth_token):
    user = User.verify_auth_token(auth_token)
    session = Session.query.filter_by(requesterID=user.id, help_status=3).first()
    return [Company.query.filter_by(id=session.companyID).first().name,
            User.query.filter_by(id=session.helperID).first().name]
