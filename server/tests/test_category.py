from tests.base import BaseTestCase

class CategoryTestCase(BaseTestCase):
    def test_get_categories(self):
        res = self.client.get("/api/categories")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.get_json(), list)
