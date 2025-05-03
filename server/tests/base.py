import unittest
from app import app, db
from models import User
from flask_jwt_extended import create_access_token

class BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app.config["TESTING"] = True
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.app.config["JWT_SECRET_KEY"] = "test-secret"
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            user = User(username="testuser", email="test@moringa.student.com")
            user.set_password("password123")
            user.assign_role()
            db.session.add(user)
            db.session.commit()
            self.user_id = user.id
            self.token = create_access_token(identity=self.user_id)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()