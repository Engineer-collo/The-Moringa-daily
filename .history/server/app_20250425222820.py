from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, Profile, Content, Category, Subscription, ContentSubscription, Wishlist, Comment, Like, Share, Notification

# Initialize the Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moringa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'f47a8a9c83bb7e58f2307e9a62b274a84b1833707c0d5d77cd02f9d7a3e16db7'  # Change this to a stronger key

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
CORS(app)  # Enable Cross-Origin Resource Sharing (if needed)
api = Api(app)
jwt = JWTManager(app)

# Home route for testing
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Moringa Social Media Platform!"})


# Protecting routes with JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Get the identity of the current user with get_jwt_identity
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(logged_in_as=user.email), 200

# API routes
from resources import UserResource, ProfileResource, ContentResource, CategoryResource, SubscriptionResource, ContentSubscriptionResource, WishlistResource, CommentResource, LikeResource, ShareResource, NotificationResource

api.add_resource(UserResource, '/users', '/users/<int:id>')
api.add_resource(ProfileResource, '/profiles', '/profiles/<int:id>')
api.add_resource(ContentResource, '/content', '/content/<int:id>')
api.add_resource(CategoryResource, '/categories', '/categories/<int:id>')
api.add_resource(SubscriptionResource, '/subscriptions', '/subscriptions/<int:id>')
api.add_resource(ContentSubscriptionResource, '/content-subscriptions', '/content-subscriptions/<int:id>')
api.add_resource(WishlistResource, '/wishlists', '/wishlists/<int:id>')
api.add_resource(CommentResource, '/comments', '/comments/<int:id>')
api.add_resource(LikeResource, '/likes', '/likes/<int:id>')
api.add_resource(ShareResource, '/shares', '/shares/<int:id>')
api.add_resource(NotificationResource, '/notifications', '/notifications/<int:id>')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
