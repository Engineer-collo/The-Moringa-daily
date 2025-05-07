from tests.base import BaseTestCase
from models import Category
from app import db

class LikeTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        with self.app.app_context():
            category = Category(name="LikeCat", description="Like category")
            db.session.add(category)
            db.session.commit()
            self.category_id = category.id

            res = self.client.post("/api/content", json={
                "title": "Likable Content",
                "body": "Please like me!",
                "content_type": "Article",
                "category_id": self.category_id
            }, headers={"Authorization": f"Bearer {self.token}"})
            self.content_id = res.get_json()["id"]

    def test_like_content(self):
        res = self.client.post("/api/like", json={
            "content_id": self.content_id
        }, headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(res.status_code, 201)
        self.assertIn("content_id", res.get_json())
