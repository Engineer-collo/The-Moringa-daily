from flask import Flask, jsonify, request, Blueprint
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Profile, Content, Category, Subscription, ContentSubscription, Wishlist, Comment, Like, Notification, Share

# Initialize the Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moringa.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '2845ee01f8ea548743a5b703c5a390737aa33896399622e6fecdc35163ab36c2'
app.config['JWT_SECRET_KEY'] = 'f47a8a9c83bb7e58f2307e9a62b274a84b1833707c0d5d77cd02f9d7a3e16db7'  # JWT Secret key (use a stronger key in production)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# Enable CORS with support for credentials
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])  # This allows credentials like cookies or headers to be sent

api = Api(app)
jwt = JWTManager(app)

# Create Blueprint for resources
resources_bp = Blueprint('resources', __name__)

# ============================= AUTH ROUTES =============================

@resources_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        # Hash the password before saving
        hashed_password = generate_password_hash(data['password'], method='sha256')
        user = User(email=data['email'], password=hashed_password)
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
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)  # Create JWT token
        return jsonify(access_token=access_token), 200
    return jsonify({"error": "Invalid credentials"}), 401

# ========================== ADMIN ROUTES ============================

@resources_bp.route('/content/<int:content_id>/approve', methods=['PATCH'])
@jwt_required()  # Require JWT token for this route
def approve_content(content_id):
    content = Content.query.get_or_404(content_id)
    content.is_approved = True
    db.session.commit()
    return jsonify(content.to_dict()), 200

@resources_bp.route('/content/<int:content_id>/flag', methods=['PATCH'])
@jwt_required()  # Require JWT token for this route
def flag_content(content_id):
    content = Content.query.get_or_404(content_id)
    content.is_flagged = True
    db.session.commit()
    return jsonify(content.to_dict()), 200

# ======================== TECHWRITER ROUTES ========================

@resources_bp.route('/content', methods=['POST'])
@jwt_required()  # Require JWT token for this route
def create_content():
    data = request.get_json()
    content = Content(**data)
    db.session.add(content)
    db.session.commit()
    return jsonify(content.to_dict()), 201

@resources_bp.route('/content/<int:content_id>', methods=['PATCH'])
@jwt_required()  # Require JWT token for this route
def update_content(content_id):
    content = Content.query.get_or_404(content_id)
    data = request.get_json()
    for key, value in data.items():
        setattr(content, key, value)
    db.session.commit()
    return jsonify(content.to_dict()), 200

@resources_bp.route('/content/<int:content_id>', methods=['DELETE'])
@jwt_required()  # Require JWT token for this route
def delete_content(content_id):
    content = Content.query.get_or_404(content_id)
    db.session.delete(content)
    db.session.commit()
    return '', 204

# ========================== STUDENT ROUTES =========================

@resources_bp.route('/categories', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def get_categories():
    return jsonify([c.to_dict() for c in Category.query.all()]), 200

@resources_bp.route('/subscribe/category/<int:category_id>', methods=['POST'])
@jwt_required()  # Require JWT token for this route
def subscribe_category(category_id):
    data = request.get_json()
    subscription = Subscription(user_id=data['user_id'], category_id=category_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

@resources_bp.route('/subscribe/content/<int:content_id>', methods=['POST'])
@jwt_required()  # Require JWT token for this route
def subscribe_content(content_id):
    data = request.get_json()
    subscription = ContentSubscription(user_id=data['user_id'], content_id=content_id)
    db.session.add(subscription)
    db.session.commit()
    return jsonify(subscription.to_dict()), 201

@resources_bp.route('/wishlist', methods=['POST'])
@jwt_required()  # Require JWT token for this route
def add_to_wishlist():
    data = request.get_json()
    wishlist = Wishlist(**data)
    db.session.add(wishlist)
    db.session.commit()
    return jsonify(wishlist.to_dict()), 201

@resources_bp.route('/comment', methods=['POST'])
@jwt_required()  # Require JWT token for this route
def post_comment():
    data = request.get_json()
    comment = Comment(**data)
    db.session.add(comment)
    db.session.commit()
    return jsonify(comment.to_dict()), 201

@resources_bp.route('/like', methods=['POST'])
@jwt_required()  # Require JWT token for this route
def like_content():
    data = request.get_json()
    like = Like(**data)
    db.session.add(like)
    db.session.commit()
    return jsonify(like.to_dict()), 201

@resources_bp.route('/share', methods=['POST'])
@jwt_required()  # Require JWT token for this route
def share_content():
    data = request.get_json()
    share = Share(**data)
    db.session.add(share)
    db.session.commit()
    return jsonify(share.to_dict()), 201

@resources_bp.route('/notifications/<int:user_id>', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def get_notifications(user_id):
    notifications = Notification.query.filter_by(user_id=user_id).all()
    return jsonify([n.to_dict() for n in notifications]), 200

# Register the Blueprint
app.register_blueprint(resources_bp, url_prefix='/api')

# Home route for testing
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Moringa Social Media Platform!"})

#get profile
@resources_bp.route('/profile', methods=['POST'])
@jwt_required()
def create_profile():
    data = request.get_json()
    current_user = get_jwt_identity()  # Get the current user's ID from the JWT token
    
    # Ensure the user does not already have a profile
    existing_profile = Profile.query.filter_by(user_id=current_user).first()
    if existing_profile:
        return jsonify({"message": "Profile already exists"}), 400

    profile = Profile(
        user_id=current_user,
        bio=data.get('bio'),
        profile_picture=data.get('profile_picture'),
        website=data.get('website'),
    )
    
    db.session.add(profile)
    db.session.commit()
    return jsonify(profile.to_dict()), 201

#





# Initialize the database tables before the first request
@app.before_first_request
def create_tables():
    with app.app_context():
        db.create_all()

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
