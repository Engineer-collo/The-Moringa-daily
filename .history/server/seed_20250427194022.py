from datetime import datetime
from app import app, db  # replace 'yourapp' with the actual module name (e.g., 'app')
from models import User, Content, Category, Profile, Subscription, ContentSubscription, Wishlist, Comment, Like, Notification, Share

def create_sample_data():
    with app.app_context():
        # Clear previous data (optional, for fresh seeding)
        db.drop_all()  # Drop all tables
        db.create_all()  # Create all tables again

        # Create some sample categories
        category1 = Category(name="Cyber-Security", description="Tech-related content")
        category2 = Category(name="Full-Stack", description="Scientific discussions and news")
        category3 = Category(name="Education", description="Learning and teaching materials")
        db.session.add_all([category1, category2, category3])

        # Create some sample users
        user1 = User(username="collins", email="collinsshunza@moringa.student.com")
        user1.set_password("123456789")
        db.session.add(user1)

        user2 = User(username="collax", email="collinsshunza@moringa.techwriter.com")
        user2.set_password("123456789")
        db.session.add(user2)

        user3 = User(username="collorazy", email="collinsshunza@moringa.admin.com")
        user3.set_password("123456789")
        db.session.add(user3)

        # Commit to ensure user IDs are generated
        db.session.commit()

        # Assign roles based on email domains
        user1.assign_role()
        user2.assign_role()
        user3.assign_role()

        # Create profiles for users
        profile1 = Profile(user_id=user1.id, bio="Tech enthusiast", profile_picture="https://i.pinimg.com/474x/eb/76/a4/eb76a46ab920d056b02d203ca95e9a22.jpg", website="https://johnsblog.com")
        profile2 = Profile(user_id=user2.id, bio="Science lover", profile_picture="https://i.pinimg.com/474x/c7/9a/37/c79a37e13ef14be556b51143bcbb1b01.jpg", website="https://janespace.com")
        profile3 = Profile(user_id=user3.id, bio="Administrator at Moringa", profile_picture="https://i.pinimg.com/474x/15/b0/c5/15b0c5283d65f81adb69c09aac684554.jpg", website="https://moringa.com")
        db.session.add_all([profile1, profile2, profile3])

        # Create some sample content posts
        content1 = Content(title="The Future of AI", body="Artificial Intelligence is evolving fast...", content_type="Article", author_id=user1.id, category_id=category1.id)
        content2 = Content(title="Space Exploration", body="Humanity is moving towards the stars...", content_type="Article", author_id=user2.id, category_id=category2.id)
        content3 = Content(title="E-learning Trends", body="Online education is on the rise...", content_type="Article", author_id=user3.id, category_id=category3.id)
        db.session.add_all([content1, content2, content3])
        db.session.commit()  # Ensure content records are committed before creating comments

        # Check content IDs
        print(content1.id, content2.id, content3.id)

        # Create sample comments
        comment1 = Comment(user_id=user1.id, content_id=content2.id, body="This is a great read!")
        comment2 = Comment(user_id=user2.id, content_id=content1.id, body="Interesting perspective!")
        db.session.add_all([comment1, comment2])

        # Commit all the changes to the database
        db.session.commit()

if __name__ == "__main__":
    create_sample_data()
    print("Sample data created successfully!")
