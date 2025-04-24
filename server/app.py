from flask import Flask
from flask_restful import Api
from flask_cors import CORS  # Import CORS

from extensions import db, migrate, jwt
from resources import Register, Login

# Create the Flask app
app = Flask(__name__)

# Enable CORS with support for credentials and specific frontend origin
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])

# App configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moringa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'f47a8a9c83bb7e58f2307e9a62b274a84b1833707c0d5d77cd02f9d7a3e16db7'

# Optional: Session cookie config if you're using session/cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS

# Initialize extensions
db.init_app(app)
migrate.init_app(app, db)
jwt.init_app(app)

# Register API resources
api = Api(app)
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')

# Ensure tables are created
with app.app_context():
    db.create_all()

# Run the app
if __name__ == '_main_':
    app.run(port=5000, debug=True)