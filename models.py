from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime
import re
from passlib.hash import bcrypt_sha256
from sqlalchemy.ext.hybrid import hybrid_property

metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)

class UserRole:
    EMPLOYEE = 'employee'
    ADMIN = 'admin'

class User(db.Model, SerializerMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(150), nullable=False)
    lastname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    _password = db.Column('password', db.String(150), nullable=False)
    role = db.Column(db.String(20), default=UserRole.EMPLOYEE)

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plaintext_password):
        self._password = bcrypt_sha256.hash(plaintext_password)

    def check_password(self, plaintext_password):
        return bcrypt_sha256.verify(plaintext_password, self._password)

    @classmethod
    def authenticate(cls, email, password, role):
        user = cls.query.filter_by(email=email).first()
        if user and user.role == role.lower() and user.check_password(password):
            return user
        return None

    @validates('email')
    def validate_email(self, key, email):
        if not email:
            raise ValueError("Email is required")
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("Invalid email format")

        existing_user = User.query.filter(User.email == email).first()
        if existing_user and existing_user.id != self.id:
            raise ValueError("Email address is already registered")

        return email.lower()

    @validates('password')
    def validate_password(self, key, password):
        if not password:
            raise ValueError("Password is required")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return password

    def to_dict(self):
        return {
            'id': self.id,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'email': self.email,
            'role': self.role,
        }

class ActivityLog(db.Model):
    __tablename__ = 'activity_log'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='activity_logs')
    user_firstname = db.Column(db.String(150), nullable=True)
    user_lastname = db.Column(db.String(150), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<ActivityLog id={self.id}, user_id={self.user_id}, user_firstname={self.user_firstname}, user_lastname={self.user_lastname}, action='{self.action}', timestamp={self.timestamp}>"

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_firstname': self.user.firstname if self.user else self.user_firstname,
            'user_lastname': self.user.lastname if self.user else self.user_lastname,
            'action': self.action,
            'timestamp': self.timestamp.isoformat(),
        }

class Admin(db.Model, SerializerMixin):
    __tablename__ = 'admin'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)

    user = db.relationship("User", backref="admin")

class Employee(db.Model, SerializerMixin):
    __tablename__ = 'employee'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)

    user = db.relationship("User", backref="employee")

def populate_admin_from_users():
    # Get all users who have the role of admin
    admin_users = User.query.filter_by(role=UserRole.ADMIN).all()

    # Create Admin objects and add them to session
    for user in admin_users:
        admin = Admin(user_id=user.id)
        db.session.add(admin)

    # Commit the changes
    db.session.commit()

def populate_employee_from_users():
    # Get all users who have the role of employee
    employee_users = User.query.filter_by(role=UserRole.EMPLOYEE).all()

    # Create Employee objects and add them to session
    for user in employee_users:
        employee = Employee(user_id=user.id)
        db.session.add(employee)

    # Commit the changes
    db.session.commit()

if __name__ == "__main__":
    # Initialize Flask app and SQLAlchemy
    # Replace with your Flask app initialization
    # app = Flask(__name__)
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'your_database_uri_here'
    # db.init_app(app)

    # Create database tables
    db.create_all()

    # Populate Admin and Employee tables from User table
    populate_admin_from_users()
    populate_employee_from_users()

    print("Database schema created and Admin/Employee tables populated successfully.")
