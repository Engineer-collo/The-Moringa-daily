from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password_hash = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False, default='user')  # Default role is 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_role_based_on_email(self):
        if self.email.endswith('@admin.com'):
            self.role = 'admin'
        elif self.email.endswith('@techwriter.com'):
            self.role = 'tech_writer'
        else:
            self.role = 'user'

class Content(db.Model):
    __tablename__ = 'contents'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    body = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)

    author = db.relationship('User', backref='contents')
    category = db.relationship('Category', backref='contents')
    comments = db.relationship('Comment', backref='content', cascade='all, delete-orphan')
    likes_dislikes = db.relationship('LikeDislike', backref='content', cascade='all, delete-orphan')
    wishlists = db.relationship('Wishlist', backref='content', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Content {self.title} ({self.type})>"

class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

    def __repr__(self):
        return f"<Category {self.name}>"

class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('contents.id'), nullable=False)

    author = db.relationship('User', backref='comments')
    content = db.relationship('Content', backref='comments')

    def __repr__(self):
        return f"<Comment {self.content[:20]}...>"

class LikeDislike(db.Model):
    __tablename__ = 'likes_dislikes'

    id = db.Column(db.Integer, primary_key=True)
    is_like = db.Column(db.Boolean, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('contents.id'), nullable=False)

    user = db.relationship('User', backref='likes_dislikes')
    content = db.relationship('Content', backref='likes_dislikes')

    def __repr__(self):
        return f"<LikeDislike by User {self.user_id} on Content {self.content_id} - {'Like' if self.is_like else 'Dislike'}>"

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user = db.relationship('User', backref='notifications')

    def __repr__(self):
        return f"<Notification to User {self.user_id} - Read: {self.is_read}>"

class Wishlist(db.Model):
    __tablename__ = 'wishlists'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('contents.id'), nullable=False)

    user = db.relationship('User', backref='wishlist_items')
    content = db.relationship('Content', backref='wishlist_entries')

    def __repr__(self):
        return f"<Wishlist - User {self.user_id} saved Content {self.content_id}>"

class FlaggedContent(db.Model):
    __tablename__ = 'flagged_contents'

    id = db.Column(db.Integer, primary_key=True)
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('contents.id'), nullable=False)

    user = db.relationship('User', backref='flagged_contents')
    content = db.relationship('Content', backref='flagged_entries')

    def __repr__(self):
        return f"<FlaggedContent by User {self.user_id} on Content {self.content_id}>"

class Share(db.Model):
    __tablename__ = 'shares'

    id = db.Column(db.Integer, primary_key=True)
    content_id = db.Column(db.Integer, db.ForeignKey('contents.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    content = db.relationship('Content', backref='shares')
    user = db.relationship('User', backref='shares')

    def __repr__(self):
        return f"<Share - User {self.user_id} shared Content {self.content_id}>"
