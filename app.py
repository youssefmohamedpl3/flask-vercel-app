from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import secrets
from datetime import datetime, timedelta
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_PERMANENT'] = True

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, id, username, password, accessible_students):
        self.id = id
        self.username = username
        self.password = password
        self.accessible_students = accessible_students

# Users
users = {
    'admin': User('1', 'Youssef Mohamed Ahmed', 'c29FLBV593', 'all'),
    'MMM': User('2', 'Mahmoud Mohamed Mahmoud', 'aynal18', [3, 2])
}

# Student data
students = [
    {'id': 2, 'name': 'Karam Hazem Zaki Mushtaha', 'phone': '01009431618', 'address': 'Shobra', 'instagram': 'https://www.instagram.com/karam.hazem.10/', 'facebook': 'https://www.facebook.com/karam.hazem.10', 'dob': '2011-02-05', 'car': ''},
    {'id': 3, 'name': 'Mahmoud Mohamed Mahmoud', 'phone': '01090968876', 'address': 'Awsim', 'instagram': 'https://www.instagram.com/mahmoud_______2011/', 'facebook': 'https://www.facebook.com/profile.php?id=100050581157620', 'dob': '2011-08-28', 'car': 'Hyundai Elantra 2020'},
    {'id': 5, 'name': 'Malek Hany Abdelal', 'phone': '01122206125', 'address': 'Faisal Mariouteya', 'instagram': 'https://www.instagram.com/itz_____malek/', 'facebook': 'https://www.facebook.com/profile.php?id=100055797635744', 'dob': '2011-10-11', 'car': ''},
    {'id': 4, 'name': 'Layan Wael Mohamed', 'phone': '01554918118', 'address': 'Faisal Mariouteya', 'instagram': '', 'facebook': 'https://www.facebook.com/lian.wael.14', 'dob': '2011-08-01', 'car': ''},
    {'id': 1, 'name': 'Sandy Wassim Abdullah', 'phone': '01030064939', 'address': 'Egypt, Cairo, Sheikh Zayed, 8th district', 'instagram': 'https://www.instagram.com/sandy_wasiem12/', 'facebook': 'https://www.facebook.com/profile.php?id=61550241764159&mibextid=ZbWKwL', 'dob': '2011-07-01', 'car': ''}
]

# Store user activity globally
user_activity = {}

@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if user.id == user_id:
            return user
    return None

# Token generation and validation
def generate_token(student_id):
    token = secrets.token_urlsafe(16)
    session[f'token_{student_id}'] = {'token': token, 'expires': (datetime.now() + timedelta(minutes=5)).timestamp()}
    return token

def validate_token(student_id, token):
    token_data = session.get(f'token_{student_id}')
    if not token_data or token_data['token'] != token or datetime.now().timestamp() > token_data['expires']:
        return False
    return True

# Check session expiration
def check_session_expiration():
    if current_user.is_authenticated:
        last_activity = session.get('last_activity')
        if last_activity:
            last_activity_time = datetime.fromtimestamp(last_activity)
            if datetime.now() - last_activity_time > app.config['PERMANENT_SESSION_LIFETIME']:
                if current_user.username in user_activity:
                    user_activity[current_user.username]['logout_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                session.clear()
                logout_user()
        session['last_activity'] = datetime.now().timestamp()
        session.modified = True

@app.before_request
def before_request():
    check_session_expiration()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user.password == password:
            login_user(user)
            session['accessed_students'] = []
            session['last_activity'] = datetime.now().timestamp()
            user_activity[user.username] = {
                'login_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'logout_time': None,
                'students_checked': []
            }
            logger.info(f"User '{user.username}' logged in from IP: {request.remote_addr}")
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if current_user.username in user_activity:
        user_activity[current_user.username]['logout_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info(f"User '{current_user.username}' logged out.")
    session.clear()
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    if current_user.username == 'Youssef Mohamed Ahmed':
        return render_template('admin_dashboard.html', users=users, user_activity=user_activity)
    else:
        if current_user.accessible_students == 'all':
            filtered_students = students
        else:
            filtered_students = [s for s in students if s['id'] in current_user.accessible_students]
        student_tokens = {student['id']: generate_token(student['id']) for student in filtered_students}
        return render_template('index.html', students=filtered_students, tokens=student_tokens)

@app.route('/student', methods=['POST'])
@login_required
def student_detail():
    student_id = int(request.form['student_id'])
    token = request.form['token']
    
    if not validate_token(student_id, token):
        return 'Invalid or expired token', 403
    
    student = next((s for s in students if s['id'] == student_id), None)
    if not student:
        return 'Student not found', 404
    
    if current_user.accessible_students != 'all' and student['id'] not in current_user.accessible_students:
        return 'Unauthorized access', 403
    
    if current_user.username in user_activity:
        user_activity[current_user.username]['students_checked'].append({
            'id': student_id,
            'name': student['name'],
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return render_template('student.html', student=student)

@app.route('/clear_activity', methods=['POST'])
@login_required
def clear_activity():
    if current_user.username != 'Youssef Mohamed Ahmed':
        return 'Unauthorized', 403
    user_activity.clear()
    logger.info("Admin cleared all user activity data.")
    flash('All user activity data has been cleared.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)