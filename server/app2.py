from flask import Flask, jsonify, request, Blueprint
from flask_migrate import Migrate
from flask_cors import CORS, cross_origin
from flask_restful import Api
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from flasgger import Swagger
from datetime import timedelta
import os

from models import db, User, Profile, Content, Category, Subscription, ContentSubscription, Wishlist, Comment, Like, Notification, Share, Conversation, Message
from config import JWT_SECRET_KEY, SQLALCHEMY_DATABASE_URI
from cloudinary_utils.video_upload import video_upload_bp

# ========== EXTENSION INSTANCES ==========
# db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
api = Api()
socketio = SocketIO(cors_allowed_origins="*")

# ========== APP SETUP ==========
app = Flask(__name__, instance_relative_config=True)
app.config.from_object('config')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY

# Initialize extensions
db.init_app(app)
migrate.init_app(app, db)
jwt.init_app(app)
api.init_app(app)
socketio.init_app(app)
Swagger(app, template_file=os.path.join('docs', 'swagger.yml'))

# CORS
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)

# Register media upload blueprint
app.register_blueprint(video_upload_bp, url_prefix='/api/video_upload')

# Define routes blueprint
resources_bp = Blueprint('resources', __name__)

# JWT Blocklist
jwt_blocklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload.get('jti')
    return jti in jwt_blocklist

@app.errorhandler(Exception)
def handle_exception(error):
    return jsonify({'error': str(error)}), 500

# ========== Paste All Your Routes Below This Line ========== #
# Register, Login, Logout, User routes are already included above.
# Paste the rest of your profile, content, category, subscriptions, etc. routes here.
# Make sure all routes use @resources_bp.route(...)

@resources_bp.route('/user', methods=['GET'])
@jwt_required()
def get_user_data():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if user:
            return jsonify(user.to_dict()), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@resources_bp.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user or user.role != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200

# ========== AUTH ROUTES ==========

@resources_bp.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
    data = request.get_json()
    if 'username' not in data or not data['username']:
        return jsonify({'error': 'Username is required'}), 400
    if 'email' not in data or not data['email']:
        return jsonify({'error': 'Email is required'}), 400
    if 'password' not in data or not data['password']:
        return jsonify({'error': 'Password is required'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    try:
        user = User(
            username=data['username'],
            email=data['email'],
            password=generate_password_hash(data['password'], method='pbkdf2:sha256')
        )
        user.assign_role()
        db.session.add(user)
        db.session.commit()
        return jsonify(user.to_dict()), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@resources_bp.route('/login', methods=['POST'])
@cross_origin(origin='http://localhost:5173', supports_credentials=True)
def login():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    if user and check_password_hash(user.password, data.get('password')):
        additional_claims = {'role': user.role} if hasattr(user, 'role') else {}
        access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
        return jsonify(access_token=access_token), 200
    return jsonify({'error': 'Invalid credentials'}), 401

@resources_bp.route('/logout ', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt().get('jti')
    jwt_blocklist.add(jti)
    return jsonify({'message': 'Successfully logged out'}), 200

# ========== PROFILE ROUTES ==========

@resources_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    profile = Profile.query.filter_by(user_id=current_user).first()
    if profile:
        return jsonify(profile.to_dict()), 200
    return jsonify({'message': 'Profile not found'}), 404

@resources_bp.route('/profile', methods=['POST'])
@jwt_required()
def create_profile():
    data = request.get_json()
    current_user = get_jwt_identity()
    if Profile.query.filter_by(user_id=current_user).first():
        return jsonify({'message': 'Profile already exists'}), 400
    profile = Profile(user_id=current_user, bio=data.get('bio'), profile_picture=data.get('profile_picture'), website=data.get('website'))
    db.session.add(profile)
    db.session.commit()
    return jsonify(profile.to_dict()), 201

@resources_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    data = request.get_json()
    current_user = get_jwt_identity()
    profile = Profile.query.filter_by(user_id=current_user).first()
    if not profile:
        return jsonify({'message': 'Profile not found'}), 404
    profile.bio = data.get('bio', profile.bio)
    profile.profile_picture = data.get('profile_picture', profile.profile_picture)
    profile.website = data.get('website', profile.website)
    db.session.commit()
    return jsonify(profile.to_dict()), 200

@resources_bp.route('/profile', methods=['DELETE'])
@jwt_required()
def delete_profile():
    current_user = get_jwt_identity()
    profile = Profile.query.filter_by(user_id=current_user).first()
    if not profile:
        return jsonify({'message': 'Profile not found'}), 404
    db.session.delete(profile)
    db.session.commit()
    return jsonify({'message': 'Profile deleted'}), 200

# ========== CONTENT ROUTES ==========

@resources_bp.route('/content', methods=['POST'])
@jwt_required()
def create_content():
    data = request.get_json()
    user_id = get_jwt_identity()
    content_type = data.get('content_type')
    if not content_type:
        return jsonify({'error': 'content_type is required'}), 400
    content = Content(
        title=data.get('title'),
        body=data.get('body'),
        content_type=content_type,
        category_id=data.get('category_id'),
        author_id=user_id
    )
    db.session.add(content)
    db.session.commit()
    return jsonify(content.to_dict()), 201

@resources_bp.route('/content', methods=['GET'])
def get_all_content():
    content = Content.query.all()
    return jsonify([c.to_dict() for c in content]), 200

@resources_bp.route('/content/<int:content_id>', methods=['GET'])
def get_content_by_id(content_id):
    content = Content.query.get_or_404(content_id)
    return jsonify(content.to_dict()), 200

@resources_bp.route('/content/<int:content_id>', methods=['PATCH'])
@jwt_required()
def update_content(content_id):
    content = Content.query.get_or_404(content_id)
    data = request.get_json()
    for key, value in data.items():
        setattr(content, key, value)
    db.session.commit()
    return jsonify(content.to_dict()), 200

@resources_bp.route('/content/<int:content_id>', methods=['DELETE'])
@jwt_required()
def delete_content(content_id):
    content = Content.query.get_or_404(content_id)
    db.session.delete(content)
    db.session.commit()
    return '', 204

# ========== CATEGORY ROUTES ==========

@resources_bp.route('/categories', methods=['GET'])
def get_categories():
    return jsonify([c.to_dict() for c in Category.query.all()]), 200

@resources_bp.route('/categories', methods=['POST'])
@jwt_required()
def add_category():
    data = request.get_json()
    if 'name' not in data:
        return jsonify({'error': 'Category name is required'}), 400
    if Category.query.filter_by(name=data['name']).first():
        return jsonify({'message': 'Category already exists'}), 400
    category = Category(name=data['name'])
    db.session.add(category)
    db.session.commit()
    return jsonify(category.to_dict()), 201

# ========== SUBSCRIPTION ROUTES ==========

@resources_bp.route('/subscribe/category/<int:category_id>', methods=['POST'])
@jwt_required()
def subscribe_category(category_id):
    current_user = get_jwt_identity()
    subscription = Subscription(user_id=current_user, category_id=category_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

@resources_bp.route('/subscribe/content/<int:content_id>', methods=['POST'])
@jwt_required()
def subscribe_content(content_id):
    current_user = get_jwt_identity()
    subscription = ContentSubscription(user_id=current_user, content_id=content_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

@resources_bp.route('/subscriptions/categories', methods=['GET'])
@jwt_required()
def get_subscribed_categories():
    current_user = get_jwt_identity()
    subscriptions = Subscription.query.filter_by(user_id=current_user).all()
    categories = [Category.query.get(sub.category_id) for sub in subscriptions]
    return jsonify([c.to_dict() for c in categories]), 200

# ========== WISHLIST ROUTES ==========

@resources_bp.route('/wishlist', methods=['POST'])
@jwt_required()
def toggle_wishlist():
    data = request.get_json()
    current_user = get_jwt_identity()
    existing = Wishlist.query.filter_by(user_id=current_user, content_id=data['content_id']).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({'message': 'Removed from wishlist'}), 200
    wishlist = Wishlist(user_id=current_user, content_id=data['content_id'])
    db.session.add(wishlist)
    db.session.commit()
    return jsonify(wishlist.to_dict()), 201

@resources_bp.route('/wishlist', methods=['GET'])
@jwt_required()
def get_wishlist():
    current_user = get_jwt_identity()
    wishlist_items = Wishlist.query.filter_by(user_id=current_user).all()
    return jsonify([w.to_dict() for w in wishlist_items]), 200

# ========== LIKE_ROUTES ==========

@resources_bp.route('/like', methods=['POST'])
@jwt_required()
def like_content():
    data = request.get_json()
    current_user = get_jwt_identity()
    existing_like = Like.query.filter_by(user_id=current_user, content_id=data['content_id']).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'message': 'Like removed'}), 200
    is_like = data.get('is_like', True)
    like = Like(user_id=current_user, content_id=data['content_id'], is_like=is_like)
    db.session.add(like)
    db.session.commit()
    return jsonify(like.to_dict()), 201

@resources_bp.route('/likes', methods=['GET'])
@jwt_required()
def get_user_likes():
    current_user = get_jwt_identity()
    likes = Like.query.filter_by(user_id=current_user).all()
    return jsonify([l.to_dict() for l in likes]), 200

# ========== COMMENT ROUTES ==========

@resources_bp.route('/content/<int:content_id>/comments', methods=['GET'])
@jwt_required()
def get_threaded_comments(content_id):
    top_level = Comment.query.filter_by(content_id=content_id, parent_comment_id=None).all()
    return jsonify([build_comment_tree(comment) for comment in top_level])

def build_comment_tree(comment):
    return {
        'id': comment.id,
        'user': comment.user.username,
        'body': comment.body,
        'created_at': comment.created_at.isoformat(),
        'replies': [build_comment_tree(c) for c in comment.replies]
    }

@resources_bp.route('/comment', methods=['POST'])
@jwt_required()
def create_comment():
    data = request.get_json()
    current_user = get_jwt_identity()
    content_id = data.get('content_id')
    body = data.get('body')

    if not content_id or not body:
        return jsonify({'error': 'Missing content_id or body'}), 400

    comment = Comment(user_id=current_user, content_id=content_id, body=body)
    db.session.add(comment)
    db.session.commit()
    return jsonify(comment.to_dict()), 201


# ========== SHARE ROUTES ==========

@resources_bp.route('/share', methods=['POST'])
@jwt_required()
def share_content():
    data = request.get_json()
    current_user = get_jwt_identity()
    share = Share(user_id=current_user, content_id=data['content_id'], shared_with=data['shared_with'])
    db.session.add(share)
    db.session.commit()
    return jsonify(share.to_dict()), 201

#==============USER DEACTIVATION============#
@resources_bp.route('/admin/users/<int:user_id>/deactivate', methods=['PATCH'])
@jwt_required()
def deactivate_user(user_id):
    current_user_id = get_jwt_identity()
    admin_user = User.query.get(current_user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.active = False
    db.session.commit()
    return jsonify({'message': 'User deactivated successfully'}), 200

#==============CONTENT APPROVAL=============#
@resources_bp.route('/content/<int:content_id>/approve', methods=['POST'])
@jwt_required()
def approve_content(content_id):
    current_user_id = get_jwt_identity()
    admin_user = User.query.get(current_user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    content = Content.query.get(content_id)
    if not content:
        return jsonify({'error': 'Content not found'}), 404
    content.approved = True
    db.session.commit()
    return jsonify({'message': 'Content approved successfully'}), 200

# --- Chat System  ROUTES---
@resources_bp.route('/chats', methods=['GET'])
@jwt_required()
def get_all_chats():
    current_user = get_jwt_identity()
    chats = Conversation.query.filter((Conversation.user1_id == current_user) | (Conversation.user2_id == current_user)).all()
    return jsonify([c.id for c in chats]), 200

@resources_bp.route('/chats/<int:recipient_id>', methods=['GET', 'POST'])
@jwt_required()
def handle_chat(recipient_id):
    current_user = get_jwt_identity()

    # Check for or create the conversation
    conversation = Conversation.query.filter_by(
        user1_id=min(current_user, recipient_id),
        user2_id=max(current_user, recipient_id)
    ).first()

    if not conversation:
        if request.method == 'POST':
            conversation = Conversation(
                user1_id=min(current_user, recipient_id),
                user2_id=max(current_user, recipient_id)
            )
            db.session.add(conversation)
            db.session.commit()
        else:
            return jsonify([]), 200

    if request.method == 'POST':
        data = request.get_json()

        message = Message(
            conversation_id=conversation.id,
            sender_id=current_user,
            recipient_id=recipient_id,
            content=data['content']
        )
        db.session.add(message)
        db.session.commit()

        # Fetch both users
        sender = User.query.get(current_user)
        receiver = User.query.get(recipient_id)

        # Emit WebSocket event to all connected clients
        emit('new_chat', {
            'id': conversation.id,
            'receiverName': receiver.username,
            'lastMessage': message.content,
            'lastMessageTime': message.timestamp.isoformat(),
            'avatarUrl': receiver.profile.profile_picture if receiver.profile else None
        }, broadcast=True)

        return jsonify({'message': 'sent'}), 201

    # GET method - return conversation messages
    messages = Message.query.filter_by(conversation_id=conversation.id).all()
    return jsonify([m.content for m in messages]), 200

@resources_bp.route('/chats/shared-content', methods=['GET'])
@jwt_required()
def get_shared_content():
    current_user = get_jwt_identity()
    shares = Share.query.filter_by(user_id=current_user).all()
    return jsonify([s.to_dict() for s in shares]), 200


# ========== REGISTER ROUTES ==========
app.register_blueprint(resources_bp, url_prefix='/api')

# ========== SOCKET EVENTS ==========
@socketio.on('connect')
def on_connect():
    print('Client connected')

# ========== ENTRY POINT ==========
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
