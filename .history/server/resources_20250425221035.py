from flask import Blueprint, request, jsonify
from models import db, User, Profile, Content, Category, Subscription, ContentSubscription, Wishlist, Comment, Like, Share, Notification

resources_bp = Blueprint('resources', __name__)

# ============================= AUTH ROUTES =============================

@resources_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        user = User(email=data['email'], password=data['password'])
        user.assign_role()
        db.session.add(user)
        db.session.commit()
        return jsonify(user.to_dict()), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@resources_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and user.password == data['password']:
        return jsonify(user.to_dict()), 200
    return jsonify({"error": "Invalid credentials"}), 401

# ========================== ADMIN ROUTES ============================

@resources_bp.route('/content/<int:content_id>/approve', methods=['PATCH'])
def approve_content(content_id):
    content = Content.query.get_or_404(content_id)
    content.is_approved = True
    db.session.commit()
    return jsonify(content.to_dict()), 200

@resources_bp.route('/content/<int:content_id>/flag', methods=['PATCH'])
def flag_content(content_id):
    content = Content.query.get_or_404(content_id)
    content.is_flagged = True
    db.session.commit()
    return jsonify(content.to_dict()), 200

# ======================== TECHWRITER ROUTES ========================

@resources_bp.route('/content', methods=['POST'])
def create_content():
    data = request.get_json()
    content = Content(**data)
    db.session.add(content)
    db.session.commit()
    return jsonify(content.to_dict()), 201

@resources_bp.route('/content/<int:content_id>', methods=['PATCH'])
def update_content(content_id):
    content = Content.query.get_or_404(content_id)
    data = request.get_json()
    for key, value in data.items():
        setattr(content, key, value)
    db.session.commit()
    return jsonify(content.to_dict()), 200

@resources_bp.route('/content/<int:content_id>', methods=['DELETE'])
def delete_content(content_id):
    content = Content.query.get_or_404(content_id)
    db.session.delete(content)
    db.session.commit()
    return '', 204

# ========================== STUDENT ROUTES =========================

@resources_bp.route('/categories', methods=['GET'])
def get_categories():
    return jsonify([c.to_dict() for c in Category.query.all()]), 200

@resources_bp.route('/subscribe/category/<int:category_id>', methods=['POST'])
def subscribe_category(category_id):
    data = request.get_json()
    subscription = Subscription(user_id=data['user_id'], category_id=category_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

@resources_bp.route('/subscribe/content/<int:content_id>', methods=['POST'])
def subscribe_content(content_id):
    data = request.get_json()
    subscription = ContentSubscription(user_id=data['user_id'], content_id=content_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

@resources_bp.route('/wishlist', methods=['POST'])
def add_to_wishlist():
    data = request.get_json()
    wishlist = Wishlist(**data)
    db.session.add(wishlist)
    db.session.commit()
    return jsonify(wishlist.to_dict()), 201

@resources_bp.route('/comment', methods=['POST'])
def post_comment():
    data = request.get_json()
    comment = Comment(**data)
    db.session.add(comment)
    db.session.commit()
    return jsonify(comment.to_dict()), 201

@resources_bp.route('/like', methods=['POST'])
def like_content():
    data = request.get_json()
    like = Like(**data)
    db.session.add(like)
    db.session.commit()
    return jsonify(like.to_dict()), 201

@resources_bp.route('/share', methods=['POST'])
def share_content():
    data = request.get_json()
    share = Share(**data)
    db.session.add(share)
    db.session.commit()
    return jsonify(share.to_dict()), 201

@resources_bp.route('/notifications/<int:user_id>', methods=['GET'])
def get_notifications(user_id):
    notifications = Notification.query.filter_by(user_id=user_id).all()
    return jsonify([n.to_dict() for n in notifications]), 200
