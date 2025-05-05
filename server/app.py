from flask import Flask, jsonify, request, Blueprint
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash
from server.models import db, User, Profile, Content, Category, Subscription, ContentSubscription, Wishlist, Comment, Like, Notification, Share, Conversation, Message
from datetime import timedelta
from server.cloudinary_utils.video_upload import video_upload_bp

app = Flask(__name__, instance_relative_config=True)
app.config.from_object('server.config')

app.register_blueprint(video_upload_bp, url_prefix='/api/video_upload')

# ========== INITIALIZE EXTENSIONS ==========

db.init_app(app)
migrate = Migrate(app, db)
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])
api = Api(app)
jwt = JWTManager(app)

# ========== BLUEPRINT ==========

resources_bp = Blueprint('resources', __name__)

# ========== ERROR HANDLING ==========

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all unhandled exceptions globally"""
    return jsonify({"error": str(error)}), 500

# ========== USER ROUTES ==========

@resources_bp.route('/user', methods=['GET'])
@jwt_required()
def get_user_data():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if user:
            return jsonify(user.to_dict()), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@resources_bp.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user or user.role != 'admin':
        return jsonify({"error": "Unauthorized access"}), 403
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200

# ========== AUTH ROUTES ==========

@resources_bp.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json()
    if 'username' not in data or not data['username']:
        return jsonify({"error": "Username is required"}), 400
    if 'email' not in data or not data['email']:
        return jsonify({"error": "Email is required"}), 400
    if 'password' not in data or not data['password']:
        return jsonify({"error": "Password is required"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already registered"}), 400
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
        return jsonify({"error": str(e)}), 400

@resources_bp.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        additional_claims = {"role": user.role} if hasattr(user, 'role') else {}
        access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
        return jsonify(access_token=access_token), 200
    return jsonify({"error": "Invalid credentials"}), 401

@resources_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({"message": "Logout successful"})
    unset_jwt_cookies(response)
    return response, 200

# ========== NEW ROUTES ==========

@resources_bp.route('/subscriptions/categories', methods=['GET'])
@jwt_required()
def get_user_subscribed_categories():
    user_id = get_jwt_identity()
    subscriptions = Subscription.query.filter_by(user_id=user_id).all()
    categories = [s.category.to_dict() for s in subscriptions]
    return jsonify(categories), 200

@resources_bp.route('/wishlist', methods=['GET'])
@jwt_required()
def get_user_wishlist():
    user_id = get_jwt_identity()
    wishlist_items = Wishlist.query.filter_by(user_id=user_id).all()
    return jsonify([item.to_dict() for item in wishlist_items]), 200

# ========== ADD BLUEPRINT TO APP ==========

app.register_blueprint(resources_bp, url_prefix='/api')

if __name__ == '__main__':
    app.run(debug=True)
