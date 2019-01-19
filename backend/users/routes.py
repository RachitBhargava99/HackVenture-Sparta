from flask import Blueprint, request, current_app
from backend.models import User, Session, CheckInSession, Company
from backend import db, bcrypt, mail
import json
from backend.users.utils import send_reset_email, get_help_info, get_last_session_info,\
    get_basic_nums_a, get_help_session_info, get_last_session_info_a, check_helper_session,\
    get_remaining_check_in_time, get_hourly_info, get_last_session_info_m, get_recs_active,\
    get_current_sessions, db_updater, get_curr_help_info
from datetime import datetime, timedelta
from sqlalchemy import and_, or_
from flask_mail import Message
import random
import string

users = Blueprint('users', __name__)


@users.route('/login', methods=['GET', 'POST'])
def login():
    request_json = request.get_json()
    email = request_json['email']
    password = request_json['password']
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        final_dict = {
            'id': user.id,
            'auth_token': user.get_auth_token(),
            'name': user.name,
            'email': user.email,
            'isAdmin': user.isAdmin,
            'status': 1
        }
        return json.dumps(final_dict)
    else:
        final_dict = {
            'status': 0,
            'error': "The provided combination of email and password is incorrect."
        }
        return json.dumps(final_dict)


@users.route('/register', methods=['GET', 'POST'])
def normal_register():
    request_json = request.get_json()
    if User.query.filter_by(email=request_json['email']).first():
        return json.dumps({'status': 0, 'output': User.query.filter_by(email=request_json['email']).first().email,
                          'error': "User Already Exists"})
    elif User.query.filter_by(gt_id=request_json['gt_id']).first():
        return json.dumps({'status': 0, 'error': "The provided GeorgiaTech ID is already registered."})
    email = request_json['email']
    hashed_pwd = bcrypt.generate_password_hash(request_json['password']).decode('utf-8')
    name = request_json['name']
    gt_id = request_json['gt_id']
    # noinspection PyArgumentList
    user = User(email=email, password=hashed_pwd, name=name, gt_id=gt_id, isAdmin=False)
    db.session.add(user)
    db.session.commit()
    return json.dumps({'id': user.id, 'status': 1})


@users.route('/company/add', methods=['GET', 'POST'])
def add_company():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})

    elif not user.isMaster:
        return json.dumps({
            'status': 0,
            'error': "Access Denied"
        })
    company_name = request_json['company_name']
    rep_name = request_json['rep_name']
    rep_email = request_json['rep_email']
    num_reps = request_json['num_reps']
    website = request_json['website']
    new_company = Company(name=company_name, rep_name=rep_name, rep_email=rep_email, num_reps=num_reps, website=website)
    db.session.add(new_company)
    db.session.commit()
    return json.dumps({
        'status': 1,
        'company_id': Company.query.filter_by(name=company_name, rep_name=rep_name, rep_email=rep_email).first().id
    })


@users.route('/company/add_recruiter', methods=['GET', 'POST'])
def add_company_recruiter():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    elif not user.isAdmin:
        return json.dumps({
            'status': 0,
            'error': "Access Denied"
        })
    elif User.query.filter_by(company_id=user.company_id).count() >= Company.query.filter_by(id=user.company_id).first().num_reps:
        return json.dumps({
            'status': 0,
            'error': "Max Representatives Reached. Please contact event organizer for help."
        })
    company_id = user.company_id
    company = Company.query.filter_by(id=company_id).first()
    name = request_json['name']
    email = f"{name}@{company.name}.com"
    random_password = ''.join(
        random.choices(
            string.ascii_uppercase + string.digits + string.ascii_lowercase + string.punctuation,
            k=8
        )
    )
    hashed_pwd = bcrypt.generate_password_hash(random_password).decode('utf-8')
    new_user = User(name=name,
                    email=email,
                    password=hashed_pwd,
                    isAdmin=True,
                    company_id=company.id,
                    designation="Recruiter")
    db.session.add(new_user)
    db.session.commit()
    return json.dumps({
        'status': 1
    })


@users.route('/company/add_user', methods=['GET', 'POST'])
def add_company_user():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    elif not user.isMaster:
        return json.dumps({
            'status': 0,
            'error': "Access Denied"
        })
    company_id = request_json['company_id']
    company = Company.query.filter_by(id=company_id).first()
    name = request_json['name']
    designation = request_json['designation']
    email = request_json['email']
    random_password = ''.join(
        random.choices(
            string.ascii_uppercase + string.digits + string.ascii_lowercase + string.punctuation,
            k=8
        )
    )
    msg = Message(
        "Welcome to Helpify Corporate",
        sender="rachitb@gatech.edu",
        recipients=[email],
        body=f"""
            Hi {name},
            
            Thanks for your interest in working with us over the upcoming event!
            
            We have created a user account for you under the company {company.name}. You may log in by going to {current_app.config['CURRENT_URL']}.
            
            Your username is the email address on which you received this email, and your password is:
            {random_password}
            
            Please feel free to contact us in case of any queries.
            
            We look forward towards meeting you at the event!
            
            Regards,
            Helpify Corporate Team
            (on behalf of the event organizers)
        """
    )
    mail.send(msg)
    hashed_pwd = bcrypt.generate_password_hash(random_password).decode('utf-8')
    new_user = User(name=name,
                    email=email,
                    password=hashed_pwd,
                    isAdmin=True,
                    company_id=company.id,
                    designation=designation)
    db.session.add(new_user)
    db.session.commit()
    return json.dumps({
        'status': 1
    })


@users.route('/company/list_active', methods=['GET', 'POST'])
def get_active_company_list():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    activity_status = True if Session.query.filter_by(requesterID=user.id, help_status=0).first() else False
    last_session = get_last_session_info(auth_token)

    if activity_status:
        request_help = get_help_info(auth_token)
        data = {
            'company_name': Company.query.filter_by(
                id=Session.query.filter_by(requesterID=user.id, help_status=0).first().companyID).first().name,
            'company_website': Company.query.filter_by(
                id=Session.query.filter_by(requesterID=user.id, help_status=0).first().companyID).first().website,
            'current_helpers_active': request_help[0],
            'current_wait_time': request_help[1],
            'current_queue_pos': request_help[2],
            'last_session_date': last_session[0],
            'last_session_helper': last_session[1],
            'last_session_designation': last_session[2],
            'last_session_company': last_session[3],
            'status': 1
        }
        return json.dumps({'status': 1,
                           'basics': data,
                           'output': {},
                           'activity_status': activity_status})

    activity_status = True if Session.query.filter_by(requesterID=user.id, help_status=3).first() else False

    if activity_status:
        request_help = get_curr_help_info(auth_token)
        data = {
            'company_name': request_help[0],
            'rec_name': request_help[1],
            'last_session_date': last_session[0],
            'last_session_helper': last_session[1],
            'last_session_designation': last_session[2],
            'last_session_company': last_session[3],
            'status': 2
        }
        return json.dumps({'status': 1,
                           'basics': data,
                           'output': {},
                           'activity_status': activity_status})

    active_admins = User.query.filter_by(isAdmin=True, isActive=True)
    company_ids = {}
    for each in active_admins:
        company_ids[each.company_id] = User.query.filter_by(company_id=each.company_id, isActive=True).count()
    final = []
    num = 1
    for each in company_ids:
        final.append({
            'num': num,
            'id': each,
            'name': Company.query.filter_by(id=each).first().name,
            'num_helpers': company_ids[each],
            'queue_length': Session.query.filter_by(companyID=each, help_status=0).count()
        })
        num += 1
    data = {
        'last_session_date': last_session[0],
        'last_session_helper': last_session[1],
        'last_session_designation': last_session[2],
        'last_session_company': last_session[3]
    }
    return json.dumps({'status': 1,
                       'basics': data,
                       'output': final,
                       'activity_status': activity_status})


@users.route('/company/all', methods=['GET', 'POST'])
def get_all_companies():
    request_json = request.get_json()
    user = User.verify_auth_token(request_json['auth_token'])
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    elif not user.isMaster:
        return json.dumps({'status': 0,
                           'error': "Access Denied"})
    else:
        companies = Company.query.all()
        final = [(x.id, x.name) for x in companies]
        return json.dumps({'status': 1,
                           'choices': final})


@users.route('/company/all/calling', methods=['GET'])
def all_companies_calling():
    active_admins = User.query.filter_by(isAdmin=True, isActive=True)
    company_ids = {}
    for each in active_admins:
        company_ids[each.company_id] = User.query.filter_by(company_id=each.company_id, isActive=True).count()
    final = []
    num = 1
    for each in company_ids:
        calling = Session.query.filter_by(companyID=each, help_status=3)
        users_calling = [User.query.filter_by(id=x.requesterID).first().name for x in calling]
        final.append({
            'num': num,
            'id': each,
            'name': Company.query.filter_by(id=each).first().name,
            'num_helpers': company_ids[each],
            'queue_length': Session.query.filter_by(companyID=each, help_status=0).count(),
            'calling': str(users_calling)[1:-1] if len(users_calling) != 0 else ''
        })
        num += 1
    return json.dumps({'status': 1,
                       'output': final})



@users.route('/master/add', methods=['GET', 'POST'])
def master_add():
    request_json = request.get_json()
    user = User.query.filter_by(gt_id=request_json['gt_id']).first()
    user.isMaster = True
    db.session.commit()
    return json.dumps({'status': 1})


@users.route('/password/request_reset', methods=['GET', 'POST'])
def request_reset_password():
    request_json = request.get_json()
    user = User.query.filter_by(email=request_json['email']).first()
    if user:
        send_reset_email(user)
        return json.dumps({'status': 1})
    else:
        return json.dumps({'status': 0, 'error': "User Not Found"})


@users.route('/backend/password/verify_token', methods=['GET', 'POST'])
def verify_reset_token():
    request_json = request.get_json()
    user = User.verify_reset_token(request_json['token'])
    if user is None:
        return json.dumps({'status': 0, 'error': "Sorry, the link is invalid or has expired. Please submit password reset request again."})
    else:
        return json.dumps({'status': 1})


@users.route('/backend/password/reset', methods=['GET', 'POST'])
def reset_password():
    request_json = request.get_json()
    user = User.verify_reset_token(token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Sorry, the link is invalid or has expired. Please submit password reset request again."})
    else:
        hashed_pwd = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_pwd
        db.session.commit()
        return json.dumps({'status': 1})

@users.route('/dashboard', methods=['GET', 'POST'])
def get_dashboard_info():
    request_json = request.get_json()
    user = User.verify_auth_token(request_json['auth_token'])
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    else:
        if user.isMaster:
            return json.dumps({'status': 1,
                               'user': "Master"})
        elif user.isAdmin:
            return json.dumps({'status': 1,
                               'user': "Admin"})
        else:
            return json.dumps({'status': 1,
                               'user': "Normal"})


@users.route('/master/dashboard/info', methods=['GET', 'POST'])
def get_master_dash_info():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    elif not user.isMaster:
        return json.dumps({'status': 0,
                           'error': "Access Denied"})
    else:
        num_total_sessions = Session.query.count()
        num_no_show_sessions = Session.query.filter_by(help_status=2).count()
        num_success_sessions = Session.query.filter_by(help_status=1).count()

        num_hourly = get_hourly_info(auth_token)

        last_session = get_last_session_info_m(auth_token)

        num_company = len(Company.query.all())
        num_recruiter = User.query.filter_by(isMaster=False, isAdmin=True).count()
        num_candidate = User.query.filter_by(isMaster=False, isAdmin=False).count()
        num_session = Session.query.filter_by(help_status=1).count()

        final = {
            'total': num_total_sessions,
            'no_show': num_no_show_sessions,
            'success': num_success_sessions,
            'success_percent': int(num_success_sessions * 100 / num_total_sessions) if num_total_sessions != 0 else 100,
            'hourly_info': num_hourly,
            'success_hourly_info': [x[0] for x in num_hourly.values()],
            'noshow_hourly_info': [x[1] for x in num_hourly.values()],
            'last_session_date': last_session[0],
            'last_session_requester': last_session[1],
            'last_session_helper': last_session[2],
            'last_session_company': last_session[3],
            'num_company': num_company,
            'num_recruiter': num_recruiter,
            'num_candidate': num_candidate,
            'total_sessions': num_session
        }

        return json.dumps({'status': 1,
                           'output': final})


@users.route('/admin/dashboard/info', methods=['GET', 'POST'])
def get_admin_dash_info():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(request_json['auth_token'])

    db_updater(auth_token)

    num_session = get_basic_nums_a(auth_token)
    check_helper_session(auth_token)
    active_status = user.isActive
    online_recs = get_recs_active(auth_token)
    last_session = get_last_session_info_a(auth_token)
    curr_sessions = get_current_sessions(auth_token)

    final = {'status': 1,
             'queue_length': num_session[0],
             'helpers_active': num_session[1],
             'estimated_wait_time': num_session[2],
             'sessions_today': num_session[3],
             'last_session_date': last_session[0],
             'last_session_requester': last_session[1],
             'online_recs': online_recs,
             'curr_sessions': curr_sessions,
             'user': "Admin"
             }

    return json.dumps(final)

    # if active_status or Session.query.filter(or_(and_(Session.helperID == user.id, Session.help_status == 3),
    #                                              and_(Session.helperID == user.id, Session.help_status == 4))).first():
    #     recur = True
    #     while recur:
    #         check_session = Session.query.filter(and_(or_(and_(Session.helperID == user.id, Session.help_status == 4),
    #                                                  and_(Session.helperID == user.id, Session.help_status == 3),
    #                                                  Session.help_status == 0), Session.companyID == user.company_id))
    #         new_session = check_session.first()
    #         if new_session:
    #             new_session.helperID = user.id
    #             current_time = datetime.now()
    #             if new_session.help_status == 0:
    #                 new_session.help_status = 3
    #                 new_session.timestamp = current_time
    #                 recur = False
    #             elif new_session.help_status == 3:
    #                 time_60_seconds_back = current_time - timedelta(seconds=60)
    #                 if new_session.timestamp < time_60_seconds_back:
    #                     new_session.help_status = 4
    #                     new_session.timestamp = current_time
    #                 recur = False
    #             elif new_session.help_status == 4:
    #                 time_10_minutes_back = current_time - timedelta(minutes=10)
    #                 if new_session.timestamp < time_10_minutes_back:
    #                     new_session.help_status = 1
    #                     new_session.timestamp = current_time
    #                     if not active_status:
    #                         db.session.commit()
    #                         recur = False
    #
    #                         last_session = get_last_session_info_a(auth_token)
    #
    #                         return json.dumps({
    #                             'activity_status': False
    #                         })
    #                 else:
    #                     recur = False
    #             db.session.commit()
    #         else:
    #             recur = False
    #
    #             last_session = get_last_session_info_a(auth_token)
    #
    #             time_remaining = get_remaining_check_in_time(auth_token) if active_status else 0
    #             seconds_remaining = time_remaining.seconds if time_remaining != 0 else 0
    #             minutes_remaining = seconds_remaining // 60
    #
    #             return json.dumps({
    #                 'status': 1,
    #                 'queue_length': num_session[0],
    #                 'helpers_active': num_session[1],
    #                 'estimated_wait_time': num_session[2],
    #                 'sessions_today': num_session[3],
    #                 'minutes_remaining': minutes_remaining,
    #                 'requester_name': "No Candidate Around",
    #                 'help_time_left': 60,
    #                 'last_session_date': str(last_session[0]),
    #                 'last_session_requester': last_session[1],
    #                 'online_recs': online_recs,
    #                 'user': "Admin",
    #                 'activity_status': True,
    #                 'help_status': 3
    #             })
    #     help_session = get_help_session_info(auth_token)
    #
    #     last_session = get_last_session_info_a(auth_token)
    #
    #     time_remaining = get_remaining_check_in_time(auth_token) if active_status else 0
    #     seconds_remaining = time_remaining.seconds if time_remaining != 0 else 0
    #     minutes_remaining = seconds_remaining // 60
    #
    #     return json.dumps({'status': 1,
    #                        'help_status': new_session.help_status,
    #                        'queue_length': num_session[0],
    #                        'helpers_active': num_session[1],
    #                        'estimated_wait_time': num_session[2],
    #                        'sessions_today': num_session[3],
    #                        'minutes_remaining': minutes_remaining,
    #                        'requester_name': help_session[0],
    #                        'help_time_left': 60 if new_session.help_status == 3 else 600,
    #                        'last_session_date': last_session[0],
    #                        'last_session_requester': last_session[1],
    #                        'online_recs': online_recs,
    #                        'user': "Admin",
    #                        'activity_status': True})
    # else:
    #     last_session = get_last_session_info_a(auth_token)
    #
    #     return json.dumps({'status': 1,
    #                        'queue_length': num_session[0],
    #                        'helpers_active': num_session[1],
    #                        'estimated_wait_time': num_session[2],
    #                        'sessions_today': num_session[3],
    #                        'last_session_date': last_session[0],
    #                        'last_session_requester': last_session[1],
    #                        'online_recs': online_recs,
    #                        'user': "Admin",
    #                        'activity_status': False})


@users.route('/no_show', methods=['GET', 'POST'])
def mark_no_show():
    request_json = request.get_json()
    user = User.verify_auth_token(request_json['auth_token'])
    if not user:
        return json.dumps({
            'status': 0,
            'error': "User could not be authenticated. Please log in again."
        })
    session = Session.query.filter_by(id=request_json['session_id']).first()
    session.help_status = 2
    db.session.commit()
    return json.dumps({
        'status': 1
    })


@users.route('/done', methods=['GET', 'POST'])
def mark_done():
    request_json = request.get_json()
    user = User.verify_auth_token(request_json['auth_token'])
    if not user:
        return json.dumps({
            'status': 0,
            'error': "User could not be authenticated. Please log in again."
        })
    session = Session.query.filter_by(id=request_json['session_id']).first()
    session.help_status = 1
    db.session.commit()
    return json.dumps({
        'status': 1
    })


@users.route('/check_in', methods=['GET', 'POST'])
def check_in():
    request_json = request.get_json()
    user = User.verify_auth_token(request_json['auth_token'])
    if not user:
        return json.dumps({
            'status': 0,
            'error': "User could not be authenticated. Please log in again."
        })
    elif request_json['type'] == 1:
        company_users = User.query.filter_by(company_id=user.company_id)
        for each in company_users:
            check_in_session = CheckInSession(userID=each.id)
            db.session.add(check_in_session)
            each.isActive = True
        db.session.commit()
        return json.dumps({
            'status': 1
        })
    else:
        curr_user = User.query.filter_by(id=request_json['user_id']).first()
        check_in_session = CheckInSession(userID=curr_user.id)
        db.session.add(check_in_session)
        curr_user.isActive = True
        db.session.commit()
        return json.dumps({
            'status': 1
        })


@users.route('/check_out', methods=['GET', 'POST'])
def check_out():
    request_json = request.get_json()
    user = User.verify_auth_token(request_json['auth_token'])
    if not user:
        return json.dumps({
            'status': 0,
            'error': "User could not be authenticated. Please log in again."
        })
    elif request_json['type'] == 1:
        company_users = User.query.filter_by(company_id=user.company_id)
        for each in company_users:
            each.isActive = False
        db.session.commit()
        return json.dumps({
            'status': 1
        })
    else:
        curr_user = User.query.filter_by(id=request_json['user_id']).first()
        curr_user.isActive = False
        db.session.commit()
        return json.dumps({
            'status': 1
        })


@users.route('/sessions', methods=['GET', 'POST'])
def get_session_data():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)

    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})

    if user.isMaster:
        all_sessions = Session.query.filter_by(help_status=1)
        final = []
        num = 1
        for session in all_sessions:
            final.append({
                'num': num,
                'candidate': User.query.filter_by(id=session.requesterID).first().name,
                'recruiter': User.query.filter_by(id=session.helperID).first().name,
                'company': Company.query.filter_by(id=session.companyID).first().name,
                'date': session.timestamp.strftime("%b %d, %Y  %I:%M %p")
            })
            num += 1
        return json.dumps({
            'status': 1,
            'output': final
        })

    elif user.isAdmin:
        all_sessions = Session.query.filter_by(helperID=user.id)
        final = []
        num = 1
        for session in all_sessions:
            cand = User.query.filter_by(id=session.requesterID).first()
            final.append({
                'num': num,
                'name': cand.name,
                'date': session.timestamp.strftime("%b %d, %Y  %I:%M %p"),
                'email': cand.email
            })
            num += 1
        return json.dumps({
            'status': 1,
            'output': final
        })

    else:
        all_sessions = Session.query.filter_by(requesterID=user.id, help_status=1)
        final = []
        num = 1
        for session in all_sessions:
            recruiter = User.query.filter_by(id=session.helperID).first()
            final.append({
                'num': num,
                'name': recruiter.name,
                'designation': recruiter.designation,
                'company': Company.query.filter_by(id=recruiter.company_id).first().name,
                'date': session.timestamp.strftime("%b %d, %Y  %I:%M %p")
            })
            num += 1
        return json.dumps({
            'status': 1,
            'output': final
        })


@users.route('/lists', methods=['GET', 'POST'])
def get_list_data():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)

    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})

    req = request_json['req']

    if req == "company":
        final = [{'id': x.id, 'name': x.name, 'max_rec': x.num_reps, 'rec_reg': User.query.filter_by(company_id=x.id).count()} for x in Company.query.all()]
    elif req == "recruiter":
        final = []
        num = 1
        for comp in Company.query.all():
            for rec in User.query.filter_by(company_id=comp.id):
                final.append({
                    'num': num,
                    'id': rec.id,
                    'name': rec.name,
                    'designation': rec.designation,
                    'company_name': comp.name,
                    'email': rec.email
                })
                num += 1
    elif req == "candidate":
        final = []
        num = 1
        for cand in User.query.filter_by(isMaster=False, isAdmin=False):
            final.append({
                'num': num,
                'id': cand.id,
                'name': cand.name,
                'email': cand.email
            })
            num += 1

    return json.dumps({
        'status': 1,
        'output': final
    })


@users.route('/users/helpers', methods=['GET', 'POST'])
def get_session_data_a():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        helpers = User.query.filter_by(isActive=True)
        final = {"rows": []}
        count = 1
        for helper in helpers:
            final["rows"].append({
                "id": count,
                "name": helper.name,
            })
            count += 1
        return json.dumps({'status': 1, 'data': final["rows"], 'user_type': "Admin" if user.isAdmin else "Normal"})


@users.route('/info/helper', methods=['GET', 'POST'])
def get_helper_info():
    request_json = request.get_json()
    helper_id = request_json['helper_id']
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        helper = User.query.filter_by(id=helper_id).first()
        if not helper.isAdmin:
            return json.dumps({'status': 0, 'error': "The requested user is not a helper."})
        total_sessions = Session.query.filter_by(helperID=helper.id).count()
        total_check_ins = CheckInSession.query.filter_by(userID=helper.id).count()

        time_1_week_back = datetime.now() - timedelta(weeks=1)
        past_7_days_sessions = Session.query.filter(Session.helperID == helper.id,
                                                      Session.timestamp > time_1_week_back,
                                                      Session.help_status == 1)
        num_helper_sessions = past_7_days_sessions.count()

        last_session = get_last_session_info_a(auth_token, helper.id)

        return json.dumps({
            'status': 1,
            'total_sessions': total_sessions,
            'total_check_ins': total_check_ins,
            'total_past_7_days_sessions': num_helper_sessions,
            'last_session_date': last_session[0],
            'last_session_topic': last_session[1],
            'last_session_requester': last_session[2],
            'name': helper.name,
            'email': helper.email,
            'gt_id': helper.gt_id
        })


@users.route('/info/requester', methods=['GET', 'POST'])
def get_requester_info():
    request_json = request.get_json()
    requester_id = request_json['requester_id']
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        requester = User.query.filter_by(id=requester_id).first()
        if requester.isAdmin or requester.isMaster:
            return json.dumps({'status': 0, 'error': "The requested user is not a requester."})
        total_sessions = Session.query.filter_by(requesterID=requester.id).count()
        total_success = Session.query.filter_by(requesterID=requester.id, help_status=1).count()

        time_1_week_back = datetime.now() - timedelta(weeks=1)
        past_7_days_sessions = Session.query.filter(Session.requesterID == requester.id,
                                                      Session.timestamp > time_1_week_back,
                                                      Session.help_status == 1)
        num_requester_sessions = past_7_days_sessions.count()

        last_session = get_last_session_info(auth_token, requester.id)

        return json.dumps({
            'status': 1,
            'total_sessions': total_sessions,
            'total_success': total_success,
            'total_past_7_days_sessions': num_requester_sessions,
            'last_session_date': last_session[0],
            'last_session_topic': last_session[1],
            'last_session_helper': last_session[2],
            'name': requester.name,
            'email': requester.email,
            'gt_id': requester.gt_id
        })


@users.route('/info/helpers', methods=['GET', 'POST'])
def get_all_helpers():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        all_helpers = User.query.filter_by(isAdmin=True)
        helper_data = []
        i = 1
        for each in all_helpers:
            helper_data.append({'num': i, 'id': each.id, 'name': each.name})
            i += 1
        return json.dumps({
            'status': 1,
            'helper_data': helper_data
        })


@users.route('/info/requesters', methods=['GET', 'POST'])
def get_all_requesters():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    elif not user.isMaster:
        return json.dumps({'status': 0, 'error': "Access Denied"})
    else:
        all_requesters = User.query.filter_by(isAdmin=False, isMaster=False)
        requester_data = []
        i = 1
        for each in all_requesters:
            requester_data.append({'num': i, 'id': each.id, 'name': each.name})
            i += 1
        return json.dumps({
            'status': 1,
            'requester_data': requester_data
        })


@users.route('/test', methods=['GET'])
def test():
    return "Hello World"
