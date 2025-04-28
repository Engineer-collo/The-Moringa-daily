from flask import Flask, jsonify, request, Blueprint
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Profile, Content, Category, Subscription, ContentSubscription, Wishlist, Comment, Like, Notification, Share
from datetime import timedelta

app = Flask(__name__)

# Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moringa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '4bfbece877bc4c6a9276b4f9f0203a45d722bbfd02728c7d823438120c8b5c91'
app.config['JWT_SECRET_KEY'] = 'd9cbf61a59b0c1e24e9fc62547c3d524c97a35d7e283c902835de5d61b126bde'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=10)  # Set the token expiration globally to 10 days

# Init
db.init_app(app)
migrate = Migrate(app, db)
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])
api = Api(app)
jwt = JWTManager(app)

resources_bp = Blueprint('resources', __name__)

# ========== AUTH ROUTES ==========

@resources_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        user = User(email=data['email'], password=hashed_password)
        user.assign_role()
        db.session.add(user)
        db.session.commit()
        return jsonify(user.to_dict()), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400  # now properly indented

@resources_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        # Create an access token with a 10-day expiration (can also be globally set)
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=10))
        return jsonify(access_token=access_token), 200
    return jsonify({"error": "Invalid credentials"}), 401

# ========== PROFILE ROUTES ==========

@resources_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    profile = Profile.query.filter_by(user_id=current_user).first()
    if profile:
        return jsonify(profile.to_dict()), 200
    return jsonify({"message": "Profile not found"}), 404

@resources_bp.route('/profile', methods=['POST'])
@jwt_required()
def create_profile():
    data = request.get_json()
    current_user = get_jwt_identity()
    if Profile.query.filter_by(user_id=current_user).first():
        return jsonify({"message": "Profile already exists"}), 400
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
        return jsonify({"message": "Profile not found"}), 404
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
        return jsonify({"message": "Profile not found"}), 404
    db.session.delete(profile)
    db.session.commit()
    return jsonify({"message": "Profile deleted"}), 200

@resources_bp.route('/content', methods=['POST'])
@jwt_required()
def create_content():
    data = request.get_json()
    user_id = get_jwt_identity()

    # Ensure content_type is provided in the data
    content_type = data.get("content_type")
    if not content_type:
        return jsonify({"message": "content_type is required"}), 400

    content = Content(
        title=data.get("title"),
        body=data.get("body"),
        content_type=content_type,  # Ensure content_type is added
        category_id=data.get("category_id"),
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
    content = Content.query.get(content_id)  # Fetch content by ID
    if not content:
        return jsonify({"message": "Content not found"}), 404
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

@resources_bp.route('/content/<int:content_id>', methods=['GET'])
@jwt_required()
def view_content(content_id):
    content = Content.query.get_or_404(content_id)
    return jsonify(content.to_dict()), 200


# ========== CATEGORY ROUTE ==========

@resources_bp.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    return jsonify([c.to_dict() for c in Category.query.all()]), 200

@resources_bp.route('/categories', methods=['POST'])
@jwt_required()
def add_category():
    data = request.get_json()
    # Ensure 'name' is provided
    if 'name' not in data:
        return jsonify({"error": "Category name is required"}), 400

    # Check if the category already exists
    if Category.query.filter_by(name=data['name']).first():
        return jsonify({"message": "Category already exists"}), 400

    category = Category(name=data['name'])
    db.session.add(category)
    db.session.commit()

    return jsonify(category.to_dict()), 201

# ========== SUBSCRIPTION ROUTES ==========

@resources_bp.route('/subscribe/category/<int:category_id>', methods=['POST'])
@jwt_required()
def subscribe_category(category_id):
    data = request.get_json()
    subscription = Subscription(user_id=data['user_id'], category_id=category_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

@resources_bp.route('/subscribe/content/<int:content_id>', methods=['POST'])
@jwt_required()
def subscribe_content(content_id):
    data = request.get_json()
    subscription = ContentSubscription(user_id=data['user_id'], content_id=content_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

# ========== WISHLIST ROUTE ==========

@resources_bp.route('/wishlist', methods=['POST'])
@jwt_required()
def add_to_wishlist():
    data = request.get_json()
    wishlist = Wishlist(**data)
    db.session.add(wishlist)
    db.session.commit()
    return jsonify(wishlist.to_dict()), 201

# ========== COMMENT ROUTE ==========

@resources_bp.route('/comment', methods=['POST'])
@jwt_required()
def post_comment():
    data = request.get_json()
    comment = Comment(**data)
    db.session.add(comment)
    db.session.commit()
    return jsonify(comment.to_dict()), 201

# ========== LIKE ROUTE ==========

@resources_bp.route('/like', methods=['POST'])
@jwt_required()
def like_content():
    data = request.get_json()
    like = Like(**data)
    db.session.add(like)
    db.session.commit()
    return jsonify(like.to_dict()), 201

# ========== SHARE ROUTE ==========

@resources_bp.route('/share', methods=['POST'])
@jwt_required()
def share_content():
    data = request.get_json()
    share = Share(**data)
    db.session.add(share)
    db.session.commit()
    return jsonify(share.to_dict()), 201

# ========== NOTIFICATION ROUTE ==========

@resources_bp.route('/notifications/<int:user_id>', methods=['GET'])
@jwt_required()
def get_notifications(user_id):
    notifications = Notification.query.filter_by(user_id=user_id).all()
    return jsonify([n.to_dict() for n in notifications]), 200

# ========== HOME ROUTE ==========











#LIKE













@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Moringa Social Media Platform!"})

# Register blueprint
app.register_blueprint(resources_bp, url_prefix='/api')

# ========== USE APP CONTEXT TO CREATE TABLES ==========

with app.app_context():
    db.create_all()

# ========== RUN APP ==========

if __name__ == '__main__':
    app.run(debug=True)
