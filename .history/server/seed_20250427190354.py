from app import db  # Assuming you have app.py where `db` is initialized
from models import User, Profile, Category, Content, Comment, Like, Share, Notification, Wishlist, Subscription, ContentSubscription  # Import models

def create_sample_data():
    # Create sample Users
    user1 = User(username='john_doe', email='john_doe@moringa.student.com', role='user')
    user1.set_password('password123')
    db.session.add(user1)

    user2 = User(username='admin_user', email='admin_user@moringa.admin.com', role='admin')
    user2.set_password('adminpassword')
    db.session.add(user2)

    user3 = User(username='tech_writer', email='tech_writer@moringa.techwriter.com', role='techwriter')
    user3.set_password('techpassword')
    db.session.add(user3)

    # Commit Users to the database
    db.session.commit()

    # Create Sample Profiles
    profile1 = Profile(user_id=user1.id, bio="Student at Moringa", profile_picture="https://example.com/pic1.jpg", website="https://johnsportfolio.com")
    profile2 = Profile(user_id=user2.id, bio="Admin at Moringa", profile_picture="https://example.com/pic2.jpg", website="https://adminmoringa.com")
    profile3 = Profile(user_id=user3.id, bio="Tech Writer at Moringa", profile_picture="https://example.com/pic3.jpg", website="https://techwriter.com")
    
    db.session.add(profile1)
    db.session.add(profile2)
    db.session.add(profile3)

    # Create Categories
    category1 = Category(name="Technology", description="All things tech")
    category2 = Category(name="Lifestyle", description="Tips for living better")
    db.session.add(category1)
    db.session.add(category2)

    # Commit profiles and categories to the database
    db.session.commit()

    # Create Content
    content1 = Content(title="Latest Tech Trends", body="An article about the latest in tech.", content_type="article", author_id=user3.id, category_id=category1.id)
    content2 = Content(title="10 Tips for Better Living", body="Some great lifestyle tips.", content_type="article", author_id=user1.id, category_id=category2.id)
    db.session.add(content1)
    db.session.add(content2)

    # Commit content to the database
    db.session.commit()

    # Create Comments
    comment1 = Comment(user_id=user1.id, content_id=content1.id, body="Great insights, thanks for sharing!")
    comment2 = Comment(user_id=user2.id, content_id=content2.id, body="I found this very helpful!")
    db.session.add(comment1)
    db.session.add(comment2)

    # Commit comments to the database
    db.session.commit()

    # Create Likes
    like1 = Like(user_id=user1.id, content_id=content1.id)
    like2 = Like(user_id=user2.id, content_id=content2.id)
    db.session.add(like1)
    db.session.add(like2)

    # Commit likes to the database
    db.session.commit()

    # Create Shares
    share1 = Share(user_id=user1.id, content_id=content1.id, shared_with="jane_doe")
    share2 = Share(user_id=user2.id, content_id=content2.id, shared_with="mark_smith")
    db.session.add(share1)
    db.session.add(share2)

    # Commit shares to the database
    db.session.commit()

    # Create Notifications
    notification1 = Notification(user_id=user1.id, message="You have a new comment on your content!", is_read=False)
    notification2 = Notification(user_id=user2.id, message="Your content has been liked!", is_read=False)
    db.session.add(notification1)
    db.session.add(notification2)

    # Commit notifications to the database
    db.session.commit()

    # Create Wishlist
    wishlist1 = Wishlist(user_id=user1.id, content_id=content1.id)
    wishlist2 = Wishlist(user_id=user2.id, content_id=content2.id)
    db.session.add(wishlist1)
    db.session.add(wishlist2)

    # Commit wishlist to the database
    db.session.commit()

    # Create Subscriptions
    subscription1 = Subscription(user_id=user1.id, category_id=category1.id)
    subscription2 = Subscription(user_id=user2.id, category_id=category2.id)
    db.session.add(subscription1)
    db.session.add(subscription2)

    # Commit subscriptions to the database
    db.session.commit()

    # Create Content Subscription
    content_subscription1 = ContentSubscription(user_id=user1.id, content_id=content1.id)
    content_subscription2 = ContentSubscription(user_id=user2.id, content_id=content2.id)
    db.session.add(content_subscription1)
    db.session.add(content_subscription2)

    # Commit content subscriptions to the database
    db.session.commit()

    print("Sample data seeded successfully!")

# Run the seeding function
if __name__ == '__main__':
    create_sample_data()
