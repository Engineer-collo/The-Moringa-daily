from tests.base import BaseTestCase
from models import Category
from app import db

class ContentTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        with self.app.app_context():
            category = Category(name="Test Category", description="Desc")
            db.session.add(category)
            db.session.commit()
            self.category_id = category.id

    def test_create_content(self):
        res = self.client.post("/api/content", json={
            "title": "Test Title",
            "body": "Test Body",
            "content_type": "Article",
            "category_id": self.category_id
        }, headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(res.status_code, 201)
        self.assertIn("title", res.get_json())

    def test_get_all_content(self):
        self.client.post("/api/content", json={
            "title": "Test",
            "body": "Body",
            "content_type": "Article",
            "category_id": self.category_id
        }, headers={"Authorization": f"Bearer {self.token}"})
        res = self.client.get("/api/content")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.get_json(), list)
