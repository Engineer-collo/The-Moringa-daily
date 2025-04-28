from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.orm import validates

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    @validates('email')
    def validate_email(self, key, email):
        if '@' not in email or '.' not in email:
            raise ValueError("Invalid email address")
        return email

    @validates('role')
    def validate_role(self, key, role):
        allowed_roles = ['user', 'admin', 'tech_writer']
        if role not in allowed_roles:
            raise ValueError(f"Role must be one of {allowed_roles}")
        return role

    def set_password(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
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

    def __repr__(self):
        return f"<User {self.email} ({self.role})>"

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
    shares = db.relationship('Share', backref='content', cascade='all, delete-orphan')
    flagged_entries = db.relationship('FlaggedContent', backref='content', cascade='all, delete-orphan')

    @validates('title')
    def validate_title(self, key, title):
        if not title or len(title) < 5:
            raise ValueError("Title must be at least 5 characters long")
        return title

    @validates('type')
    def validate_type(self, key, type):
        allowed_types = ['article', 'video', 'podcast']
        if type not in allowed_types:
            raise ValueError(f"Type must be one of {allowed_types}")
        return type

    def __repr__(self):
        return f"<Content {self.title} ({self.type})>"

class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

    @validates('name')
    def validate_name(self, key, name):
        if not name or len(name) < 3:
            raise ValueError("Category name must be at least 3 characters long")
        return name

    def __repr__(self):
        return f"<Category {self.name}>"

class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)  # Changed from `content` to `text`
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('contents.id'), nullable=False)

    author = db.relationship('User', backref='comments')
    content = db.relationship('Content', backref='comments')

    @validates('text')
    def validate_text(self, key, text):
        if not text or len(text) < 10:
            raise ValueError("Comment content must be at least 10 characters long")
        return text

    def __repr__(self):
        return f"<Comment {self.text[:20]}...>"

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

    @validates('reason')
    def validate_reason(self, key, reason):
        if not reason or len(reason) > 255:
            raise ValueError("Reason must not exceed 255 characters")
        return reason

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
