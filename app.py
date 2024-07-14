from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Api, Resource ,  reqparse, abort
from flask_login import LoginManager, login_required, current_user,logout_user
from models import db, User, ActivityLog
from flask_cors import CORS


import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

app = Flask(__name__)
app.config['SECRET_KEY'] = '2#fJ7$kd_9W!sL@0'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.environ.get("DB_URI", f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-Based Access Control (RBAC)
def role_required(role):
    def decorator(func):
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role != role:
                return jsonify({"error": "You do not have access to this resource"}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

# API Resources
class UsersResource(Resource):
    def get(self):
        users = [user.to_dict() for user in User.query.all()]
        return jsonify(users)

    def post(self):
        data = request.form

        if User.query.filter_by(email=data['email']).first():
            return {"error": "Email already exists"}, 400
        
        new_user = User(
            firstname=data['firstname'],
            lastname=data['lastname'],
            email=data['email'],
            password=User.hash_password(data['password']),
            role=data.get('role', 'Employee'),
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify(new_user.to_dict()), 201

class UserProfileResource(Resource):
    # @login_required
    def get(self, id=None):
        if id:
            user = User.query.get(id)
            if user:
                return jsonify(user.to_dict()), 200
            return {"error": "User not found"}, 404
        return jsonify(current_user.to_dict()), 200

    @role_required('admin')
    def put(self, id):
        user = User.query.get(id)
        if not user:
            return {"error": "User not found"}, 404
        
        data = request.form
        user.firstname = data.get('firstname', user.firstname)
        user.lastname = data.get('lastname', user.lastname)
        
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        
        db.session.commit()
        return jsonify(user.to_dict()), 200

    @role_required('admin')
    def delete(self, id):
        user = User.query.get(id)
        if not user:
            return {"error": "User not found"}, 404
        
        db.session.delete(user)
        db.session.commit()
        return {}, 204

class LoginResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True, help="Email cannot be blank")
        parser.add_argument('password', type=str, required=True, help="Password cannot be blank")
        parser.add_argument('role', type=str, required=True, help="Role cannot be blank")
        args = parser.parse_args()

        email = args['email']
        password = args['password']
        role = args['role']

        user = User.authenticate(email, password, role)
        if not user:
            return {'error': 'Invalid credentials'}, 401
        # Log activity
        log_entry = ActivityLog(user_id=user.id, user_firstname=user.firstname, user_lastname=user.lastname, action='login', timestamp=datetime.utcnow())
        db.session.add(log_entry)
        db.session.commit()

        return user.to_dict(), 200
    

class RegisterResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('firstName', type=str, required=True, help='First Name cannot be blank')
        parser.add_argument('lastName', type=str, required=True, help='Last Name cannot be blank')
        parser.add_argument('role', type=str, required=True, help='Role cannot be blank')
        parser.add_argument('email', type=str, required=True, help='Email cannot be blank')
        parser.add_argument('password', type=str, required=True, help='Password cannot be blank')

        args = parser.parse_args()

        # Extract data from args
        firstName = args['firstName']
        lastName = args['lastName']
        role = args['role']
        email = args['email']
        password = args['password']

        # Validate data (add more validation as per your requirements)
        if not firstName or not lastName or not role or not email or not password:
            return {'error': 'Please fill in all fields.'}, 400

        # Example validation - check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return {'error': 'Email address is already registered.'}, 400

        # Create new user instance and save to database
        new_user = User(firstname=firstName, lastname=lastName, role=role, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'Registration successful'}, 200

class UserPasswordResetResource(Resource):
    # @login_required
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
        if user:
            user.password = data['new_password']
            db.session.commit()
            return {"message": "Password reset successful"}, 200
        return {"error": "User not found"}, 404

class UserProfileUpdateResource(Resource):
    # @login_required
    def put(self):
        user = current_user
        data = request.form
        
        user.firstname = data.get('firstname', user.firstname)
        user.lastname = data.get('lastname', user.lastname)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        
        db.session.commit()
        return jsonify(user.to_dict()), 200
    
    # @role_required('admin')
    def patch(self, id):
        user = User.query.get(id)
        if not user:
            return {"error": "User not found"}, 404
        
        data = request.form
        user.firstname = data.get('firstname', user.firstname)
        user.lastname = data.get('lastname', user.lastname)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        db.session.commit()
        return jsonify(user.to_dict()), 200


    
class Logout(Resource):
    # @login_required
    def post(self):
        logout_user()  # Logs out the current user
        return {"message": "Logged out successfully"}, 200
class ActivityLogin(Resource):
    def get(self):
        # Query activity logs filtering by 'login' action
        login_logs = ActivityLog.query.filter_by(action='login').all()
        
        # Serialize the queried logs into a list of dictionaries
        serialized_login_logs = [log.to_dict() for log in login_logs]
        
        # Return JSON response
        return jsonify(serialized_login_logs)
    



# API Resource Routing

api.add_resource(UsersResource, '/users')
api.add_resource(UserProfileResource, '/user/<int:id>')
api.add_resource(RegisterResource, '/register')
api.add_resource(UserPasswordResetResource, '/password/reset')
api.add_resource(UserProfileUpdateResource, '/user/<int:id>/update')
api.add_resource(LoginResource, '/login')
api.add_resource(ActivityLogin, '/activity')
# api.add_resource(UserActivityLogResource, '/user-activity-logs/<int:user_id>')

# api.add_resource(LeaveRequestResource, '/leaves')
# api.add_resource(LeaveStatusResource, '/leaves/<int:user_id>')
# api.add_resource(LeaveApprovalResource, '/leaves/approve/<int:leave_id>')
# api.add_resource(LeaveDenialResource, '/leaves/deny/<int:leave_id>')
api.add_resource(Logout, "/logout")
# api.add_resource(OvertimeCalc, '/overtime')


# Flask-Login setup

if __name__ == "__main__":
    app.run(port=5555, debug=True)
