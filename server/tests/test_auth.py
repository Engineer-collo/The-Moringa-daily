from tests.base import BaseTestCase
import json

class AuthTestCase(BaseTestCase):
    def test_register(self):
        response = self.client.post("/api/register", json={
            "username": "nadi",
            "email": "nadi@moringa.student.com",
            "password": "test123"
        })
        print("DEBUG register response:", response.status_code, response.get_json() )
        self.assertEqual(response.status_code, 201)
        

    def test_login(self):
        response = self.client.post("/api/login", json={
            "email": "test@moringa.student.com",
            "password": "password123"
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.get_json())

