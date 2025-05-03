from tests.base import BaseTestCase

class ProfileTestCase(BaseTestCase):
    def test_create_profile(self):
        res = self.client.post("/api/profile",
            json={"bio": "Hello", "website": "https://site.com"},
            headers={"Authorization": f"Bearer {self.token}"}
        )
        self.assertEqual(res.status_code, 201)

    def test_get_profile(self):
        self.client.post("/api/profile",
            json={"bio": "Test bio"}, headers={"Authorization": f"Bearer {self.token}"}
        )
        res = self.client.get("/api/profile", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("bio", res.get_json())