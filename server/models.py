from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import validates
from werkzeug.security import generate_password_hash, check_password_hash
import json


db = SQLAlchemy()

# Centralized Serialization Mixin
class SerializableMixin:
    def to_dict(self):
        columns = self.__table__.columns.keys()
        return {column: getattr(self, column) for column in columns}

# User Model
class User(db.Model, SerializableMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False) 
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="user")
    requested_writer = db.Column(db.Boolean, default=False)
    requested_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    profile = db.relationship("Profile", back_populates="user", uselist=False)
    content_posts = db.relationship("Content", back_populates="author")
    comments = db.relationship("Comment", back_populates="user")
    notifications = db.relationship("Notification", back_populates="user")
    category_subscriptions = db.relationship("Subscription", back_populates="user")
    content_subscriptions = db.relationship("ContentSubscription", back_populates="user")
    wishlists = db.relationship("Wishlist", back_populates="user")
    shares = db.relationship("Share", back_populates="user")
    likes = db.relationship("Like", back_populates="user")

    @validates("email")
    def validate_email(self, key, email):
        allowed_domains = [
            '@moringa.student.com',
            '@moringa.admin.com',
            '@moringa.techwriter.com'
        ]
        if not any(email.endswith(domain) for domain in allowed_domains):
            raise ValueError("Invalid email domain.")
        return email

    @validates("username")
    def validate_username(self, key, username):
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long.")
        return username

    def assign_role(self):
        if self.email.endswith('@moringa.admin.com'):
            self.role = "admin"
        elif self.email.endswith('@moringa.techwriter.com'):
            self.role = "techwriter"
        else:
            self.role = "user"

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Profile Model
class Profile(db.Model, SerializableMixin):
    __tablename__ = 'profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(255))
    website = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="profile")

# Content Model
# Content Model
class Content(db.Model, SerializableMixin):
    __tablename__ = 'content'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    content_type = db.Column(db.String(50), nullable=False)
    media_urls = db.Column(db.Text)  # store JSON string
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=False)
    is_flagged = db.Column(db.Boolean, default=False)

    # Relationships
    author = db.relationship("User", back_populates="content_posts")
    category = db.relationship("Category", back_populates="content")
    comments = db.relationship("Comment", back_populates="content")
    likes = db.relationship("Like", back_populates="content")
    shares = db.relationship("Share", back_populates="content")
    subscriptions = db.relationship("ContentSubscription", back_populates="content")
    wishlists = db.relationship("Wishlist", back_populates="content")

    # Validations
    @validates("title")
    def validate_title(self, key, title):
        if len(title) < 5:
            raise ValueError("Title must be at least 5 characters long.")
        return title

    @validates("body")
    def validate_body(self, key, body):
        if not body or len(body.strip()) < 10:
            raise ValueError("Content body must be at least 10 characters long.")
        return body

    @validates("content_type")
    def validate_content_type(self, key, value):
        allowed_types = ['article', 'video', 'podcast', 'document', 'image']
        if value not in allowed_types:
            raise ValueError(f"Invalid content type. Allowed: {allowed_types}")
        return value

    # Serializer
    def to_dict(self):
        data = super().to_dict()
        try:
            data['media_urls'] = json.loads(self.media_urls) if isinstance(self.media_urls, str) else self.media_urls
        except Exception:
            data['media_urls'] = []

        data['author'] = {
            'username': self.author.username if self.author else "Unknown",
            'profile': {
                'profile_picture': self.author.profile.profile_picture if self.author and self.author.profile else None
            }
        }

        return data

# Category Model
class Category(db.Model, SerializableMixin):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)

    content = db.relationship("Content", back_populates="category")
    subscriptions = db.relationship("Subscription", back_populates="category")

    @validates("name")
    def validate_name(self, key, name):
        if not name or len(name) < 3:
            raise ValueError("Category name must be at least 3 characters long.")
        return name

# Subscription Model (for Categories)
class Subscription(db.Model, SerializableMixin):
    __tablename__ = 'subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="category_subscriptions")
    category = db.relationship("Category", back_populates="subscriptions")

# ContentSubscription Model
class ContentSubscription(db.Model, SerializableMixin):
    __tablename__ = 'content_subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="content_subscriptions")
    content = db.relationship("Content", back_populates="subscriptions")

# Wishlist Model
class Wishlist(db.Model, SerializableMixin):
    __tablename__ = 'wishlists'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="wishlists")
    content = db.relationship("Content", back_populates="wishlists")

# Comment Model
class Comment(db.Model, SerializableMixin):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=True)

    user = db.relationship("User", back_populates="comments")
    content = db.relationship("Content", back_populates="comments")
    replies = db.relationship("Comment", backref=db.backref("parent", remote_side=[id]), lazy=True)

    @validates("body")
    def validate_body(self, key, body):
        if not body or len(body.strip()) < 2:
            raise ValueError("Comment body must be at least 2 characters long.")
        return body

    def to_dict(self):
        return {
            'id': self.id,
            'content_id': self.content_id,
            'body': self.body,
            'created_at': self.created_at.isoformat(),
            'user': {
                'username': self.user.username,
                'profile_picture': self.user.profile.profile_picture if self.user.profile else None
            },
            'parent_id': self.parent_comment_id
        }


# Like Model
class Like(db.Model, SerializableMixin):
    __tablename__ = 'likes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    is_like = db.Column(db.Boolean, nullable=False, default=True)  # True = like, False = dislike
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="likes")
    content = db.relationship("Content", back_populates="likes")

# Notification Model
class Notification(db.Model, SerializableMixin):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="notifications")

    @validates("message")
    def validate_message(self, key, value):
        if not value or len(value.strip()) < 5:
            raise ValueError("Notification message must be at least 5 characters long.")
        return value

# Share Model
class Share(db.Model, SerializableMixin):
    __tablename__ = 'shares'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    shared_with = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="shares")
    content = db.relationship("Content", back_populates="shares")
    
    def to_dict(self):
        return {
            'id': self.id,
            'shared_with': self.shared_with,
            'sender': self.user.username if self.user else None,
            'content': self.content.to_dict() if self.content else None,
            'created_at': self.created_at.isoformat()
        }

#  Chat System (conversation and message models)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    messages = db.relationship('Message', backref='conversation', lazy=True)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())


