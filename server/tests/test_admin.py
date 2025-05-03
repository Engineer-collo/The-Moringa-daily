from tests.base import BaseTestCase
from models import User
from flask_jwt_extended import create_access_token
from app import db

class AdminTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        with self.app.app_context():
            admin = User(username="adminuser", email="admin@moringa.admin.com")
            admin.set_password("adminpass")
            admin.assign_role()
            db.session.add(admin)
            db.session.commit()
            self.admin_token = create_access_token(identity=admin.id)

    def test_get_all_users_as_admin(self):
        res = self.client.get("/api/admin/users", headers={
            "Authorization": f"Bearer {self.admin_token}"
        })
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.get_json(), list)
