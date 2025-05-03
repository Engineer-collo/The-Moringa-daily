from tests.base import BaseTestCase

class UserTestCase(BaseTestCase):
    def test_get_user_data(self):
        res = self.client.get("/api/user", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("email", res.get_json())
