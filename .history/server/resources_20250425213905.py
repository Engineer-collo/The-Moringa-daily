from flask import request, jsonify, make_response
from flask_restful import Resource
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User

# Assign roles based on email format
def assign_role(email):
    if email.endswith('@admin.moringa.com'):
        return 'admin'
    elif email.endswith('@docs.moringa.com') and email.startswith('writer.'):
        return 'tech writer'
    return 'user'

# Register Endpoint
class Register(Resource):
    def post(self):
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return make_response(jsonify({"error": "Email and password required"}), 400)

        if User.query.filter_by(email=email).first():
            return make_response(jsonify({"message": "User already exists"}), 409)

        hashed = generate_password_hash(password)
        role = assign_role(email)

        user = User(email=email, password_hash=hashed, role=role)
        db.session.add(user)
        db.session.commit()

        return make_response(jsonify({"message": "User registered", "role": role}), 201)

# Login Endpoint
class Login(Resource):
    def post(self):
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            return make_response(jsonify({"message": "Invalid credentials"}), 401)

        token = create_access_token(identity={"email": user.email, "role": user.role})
        return make_response(jsonify({"access_token": token}), 200)

# Protected Dashboard
class Dashboard(Resource):
    @jwt_required()
    def get(self):
        identity = get_jwt_identity()
        return make_response(jsonify({
            "message": f"Welcome {identity['email']}, role: {identity['role']}"
        }), 200)