from datetime import datetime
from app import app, db  # replace 'yourapp' with the actual module name (e.g., 'app')
from models import User, Content, Category, Profile, Subscription, ContentSubscription, Wishlist, Comment, Like, Notification, Share

def create_sample_data():
    with app.app_context():
        # Clear previous data (optional, for fresh seeding)
        db.drop_all()  # Drop all tables
        db.create_all()  # Create all tables again

        # Create some sample categories
        category1 = Category(name="Technology", description="Tech-related content")
        category2 = Category(name="Science", description="Scientific discussions and news")
        category3 = Category(name="Education", description="Learning and teaching materials")
        db.session.add_all([category1, category2, category3])

        # Create some sample users
        user1 = User(username="john_doe", email="john@moringa.student.com")
        user1.set_password("password")
        db.session.add(user1)

        user2 = User(username="jane_doe", email="jane@moringa.student.com")
        user2.set_password("password")
        db.session.add(user2)

        user3 = User(username="admin_user", email="admin@moringa.admin.com")
        user3.set_password("adminpass")
        db.session.add(user3)

        # Commit to ensure user IDs are generated
        db.session.commit()

        # Assign roles based on email domains
        user1.assign_role()
        user2.assign_role()
        user3.assign_role()

        # Create profiles for users
        profile1 = Profile(user_id=user1.id, bio="Tech enthusiast", profile_picture="john_doe_pic.jpg", website="https://johnsblog.com")
        profile2 = Profile(user_id=user2.id, bio="Science lover", profile_picture="jane_doe_pic.jpg", website="https://janespace.com")
        profile3 = Profile(user_id=user3.id, bio="Administrator at Moringa", profile_picture="admin_pic.jpg", website="https://moringa.com")
        db.session.add_all([profile1, profile2, profile3])

        # Create some sample content posts
        content1 = Content(title="The Future of AI", body="Artificial Intelligence is evolving fast...", content_type="Article", author_id=user1.id, category_id=category1.id)
        content2 = Content(title="Space Exploration", body="Humanity is moving towards the stars...", content_type="Article", author_id=user2.id, category_id=category2.id)
        content3 = Content(title="E-learning Trends", body="Online education is on the rise...", content_type="Article", author_id=user3.id, category_id=category3.id)
        db.session.add_all([content1, content2, content3])

        # Create sample subscriptions (user-subscribe-to-category)
        subscription1 = Subscription(user_id=user1.id, category_id=category1.id)
        subscription2 = Subscription(user_id=user2.id, category_id=category2.id)
        subscription3 = Subscription(user_id=user3.id, category_id=category3.id)
        db.session.add_all([subscription1, subscription2, subscription3])

        # Create sample content subscriptions (user-subscribe-to-content)
        content_subscription1 = ContentSubscription(user_id=user1.id, content_id=content1.id)
        content_subscription2 = ContentSubscription(user_id=user2.id, content_id=content2.id)
        content_subscription3 = ContentSubscription(user_id=user3.id, content_id=content3.id)
        db.session.add_all([content_subscription1, content_subscription2, content_subscription3])

        # Create sample wishlists (user-add-to-wishlist)
        wishlist1 = Wishlist(user_id=user1.id, content_id=content1.id)
        wishlist2 = Wishlist(user_id=user2.id, content_id=content2.id)
        wishlist3 = Wishlist(user_id=user3.id, content_id=content3.id)
        db.session.add_all([wishlist1, wishlist2, wishlist3])

        # Create sample comments
        comment1 = Comment(user_id=user1.id, content_id=content2.id, body="This is a great read!")
        comment2 = Comment(user_id=user2.id, content_id=content1.id, body="Interesting perspective!")
        db.session.add_all([comment1, comment2])

        # Create sample likes
        like1 = Like(user_id=user1.id, content_id=content2.id)
        like2 = Like(user_id=user2.id, content_id=content1.id)
        db.session.add_all([like1, like2])

        # Create sample notifications
        notification1 = Notification(user_id=user1.id, message="You have a new follower!", is_read=False)
        notification2 = Notification(user_id=user2.id, message="Your content was liked.", is_read=False)
        db.session.add_all([notification1, notification2])

        # Create sample shares
        share1 = Share(user_id=user1.id, content_id=content1.id, shared_with="group1@example.com")
        share2 = Share(user_id=user2.id, content_id=content2.id, shared_with="group2@example.com")
        db.session.add_all([share1, share2])

        # Commit all the changes to the database
        db.session.commit()

if __name__ == "__main__":
    create_sample_data()
    print("Sample data created successfully!")
