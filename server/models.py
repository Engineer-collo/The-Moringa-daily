from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password_hash = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False, default='user')  # Default role is 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_role_based_on_email(self):
        # Assign 'admin' role if email domain is '@admin.com'
        if self.email.endswith('@admin.com'):
            self.role = 'admin'
        # Assign 'tech_writer' role if email domain is '@techwriter.com'
        elif self.email.endswith('@techwriter.com'):
            self.role = 'tech_writer'
        # Default role is 'user' if the email domain is anything else
        else:
            self.role = 'user'
    