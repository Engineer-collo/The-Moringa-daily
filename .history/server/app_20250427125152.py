from flask import Flask, jsonify, request, Blueprint
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Profile, Content, Category, Subscription, ContentSubscription, Wishlist, Comment, Like, Notification, Share
from datetime import timedelta

app = Flask(__name__)

# ========== CONFIGURATION ==========

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moringa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '4bfbece877bc4c6a9276b4f9f0203a45d722bbfd02728c7d823438120c8b5c91'
app.config['JWT_SECRET_KEY'] = 'd9cbf61a59b0c1e24e9fc62547c3d524c97a35d7e283c902835de5d61b126bde'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=10)

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

# ================= AUTH ROUTES =================

class Register(Resource):
    def post(self):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        data = request.get_json()
        try:
            hashed_password = generate_password_hash(data['password'], method='sha256')
            user = User(email=data['email'], password=hashed_password)
            user.assign_role()
            db.session.add(user)
            db.session.commit()
            return jsonify(user.to_dict()), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 400

class Login(Resource):
    def post(self):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
        if user and check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token), 200
        return jsonify({"error": "Invalid credentials"}), 401

# ================= USER ROUTES =================

class UserData(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if user:
            return jsonify(user.to_dict()), 200
        return jsonify({"error": "User not found"}), 404

class CreateUser(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        admin_user = User.query.get(current_user_id)
        if not admin_user or admin_user.role != 'admin':
            return jsonify({"error": "Unauthorized access"}), 403
        
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(email=data['email'], password=hashed_password, role=data.get('role', 'user'))
        db.session.add(new_user)
        db.session.commit()
        return jsonify(new_user.to_dict()), 201

class DeactivateUser(Resource):
    @jwt_required()
    def patch(self, user_id):
        current_user_id = get_jwt_identity()
        admin_user = User.query.get(current_user_id)
        if not admin_user or admin_user.role != 'admin':
            return jsonify({"error": "Unauthorized access"}), 403

        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        user.active = False
        db.session.commit()
        return jsonify({"message": "User deactivated successfully"}), 200

# ================= CONTENT ROUTES =================

class ContentList(Resource):
    @jwt_required()
    def get(self):
        contents = Content.query.all()
        return jsonify([content.to_dict() for content in contents]), 200

    @jwt_required()
    def post(self):
        data = request.get_json()
        user_id = get_jwt_identity()

        content_type = data.get("content_type")
        if not content_type:
            return jsonify({"message": "content_type is required"}), 400

        content = Content(
            title=data.get("title"),
            body=data.get("body"),
            content_type=content_type,
            category_id=data.get("category_id"),
            author_id=user_id
        )

        db.session.add(content)
        db.session.commit()
        return jsonify(content.to_dict()), 201

class ContentDetail(Resource):
    def get(self, content_id):
        content = Content.query.get_or_404(content_id)
        return jsonify(content.to_dict()), 200

    @jwt_required()
    def patch(self, content_id):
        content = Content.query.get_or_404(content_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(content, key, value)
        db.session.commit()
        return jsonify(content.to_dict()), 200

    @jwt_required()
    def delete(self, content_id):
        content = Content.query.get_or_404(content_id)
        db.session.delete(content)
        db.session.commit()
        return '', 204

# ================= SHARE ROUTE =================

class ShareContent(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        current_user = get_jwt_identity()
        share = Share(user_id=current_user, content_id=data['content_id'])
        db.session.add(share)
        db.session.commit()
        return jsonify(share.to_dict()), 201

# ================= CATEGORY ROUTES =================

class CategoryList(Resource):
    def get(self):
        return jsonify([c.to_dict() for c in Category.query.all()]), 200

    @jwt_required()
    def post(self):
        data = request.get_json()
        if 'name' not in data:
            return jsonify({"error": "Category name is required"}), 400
        if Category.query.filter_by(name=data['name']).first():
            return jsonify({"message": "Category already exists"}), 400

        category = Category(name=data['name'])
        db.session.add(category)
        db.session.commit()
        return jsonify(category.to_dict()), 201

# ========== COMMENT ROUTE ==========

class PostComment(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        current_user = get_jwt_identity()
        comment = Comment(user_id=current_user, content_id=data['content_id'], text=data['text'])
        db.session.add(comment)
        db.session.commit()
        return jsonify(comment.to_dict()), 201

# ========== LIKE ROUTE ==========

class ToggleLike(Resource):
    @jwt_required()
    def post(self, content_id):
        current_user = get_jwt_identity()
        like = Like.query.filter_by(user_id=current_user, content_id=content_id).first()

        if like:
            return jsonify({"message": "Already liked"}), 400
        like = Like(user_id=current_user, content_id=content_id)
        db.session.add(like)
        db.session.commit()

        like_count = Like.query.filter_by(content_id=content_id).count()
        return jsonify({"message": "Liked successfully", "like_count": like_count}), 201

    @jwt_required()
    def delete(self, content_id):
        current_user = get_jwt_identity()
        like = Like.query.filter_by(user_id=current_user, content_id=content_id).first()

        if not like:
            return jsonify({"message": "Like not found"}), 404
        db.session.delete(like)
        db.session.commit()

        like_count = Like.query.filter_by(content_id=content_id).count()
        return jsonify({"message": "Unliked successfully", "like_count": like_count}), 200

# Register the resources to their corresponding routes
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(UserData, '/user')
api.add_resource(CreateUser, '/admin/users')
api.add_resource(DeactivateUser, '/admin/users/<int:user_id>/deactivate')
api.add_resource(ContentList, '/content')
api.add_resource(ContentDetail, '/content/<int:content_id>')
api.add_resource(ShareContent, '/share')
api.add_resource(CategoryList, '/categories')
api.add_resource(PostComment, '/comment')
api.add_resource(ToggleLike, '/content/<int:content_id>/like')

# Register the blueprint with the app
app.register_blueprint(resources_bp)

if __name__ == '__main__':
    app.run(debug=True)
