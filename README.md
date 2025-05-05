# Moringa Content Management API

## Project Description
Moringa Content Management API is a Flask-based backend application designed to manage users, profiles, and various types of content. It supports user authentication with JWT, role-based access control, content creation and management, subscriptions, comments, likes, sharing, and administrative features. The API serves as a robust foundation for building content-driven web or mobile applications.

## Features
- User registration, login, and JWT-based authentication
- Role-based user management (admin, techwriter, user)
- User profiles with bio, profile picture, and website
- Content management with support for multiple content types and categories
- Subscription system for categories and individual content
- Wishlist functionality for users to save content
- Like and comment system with threaded comments
- Content sharing with other users
- Admin features including user deactivation and content approval
- RESTful API design with error handling
- Database migrations with Flask-Migrate
- CORS support for frontend integration

## Technologies Used
- Python 3
- Flask
- Flask-RESTful
- Flask-JWT-Extended
- Flask-Migrate
- Flask-CORS
- SQLAlchemy
- SQLite (default database)
- Werkzeug (for password hashing)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd The-Moringa-daily
   ```

2. Install dependencies using pipenv:
   ```bash
   pipenv install
   pipenv shell
   ```

3. Set up the database and run migrations:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

4. Run the Flask application:
   ```bash
   python server/app.py
   ```

## Usage

- The API runs by default on `http://127.0.0.1:5000/`
- All API endpoints are prefixed with `/api`
- Use JWT tokens for authenticated routes by including them in the `Authorization` header as `Bearer <token>`

## API Endpoints Overview

### User Routes
- `GET /api/user` - Get current user data (requires JWT)
- `GET /api/admin/users` - Get all users (admin only)
- `POST /api/register` - Register a new user
- `POST /api/login` - Login and receive JWT token

### Profile Routes
- `GET /api/profile` - Get current user's profile
- `POST /api/profile` - Create profile
- `PUT /api/profile` - Update profile
- `DELETE /api/profile` - Delete profile

### Content Routes
- `POST /api/content` - Create new content (requires JWT)
- `GET /api/content` - Get all content
- `GET /api/content/<id>` - Get content by ID
- `PATCH /api/content/<id>` - Update content (requires JWT)
- `DELETE /api/content/<id>` - Delete content (requires JWT)

### Category Routes
- `GET /api/categories` - List all categories
- `POST /api/categories` - Add a new category (requires JWT)

### Subscription Routes
- `POST /api/subscribe/category/<category_id>` - Subscribe to a category (requires JWT)
- `POST /api/subscribe/content/<content_id>` - Subscribe to content (requires JWT)

### Wishlist Route
- `POST /api/wishlist` - Add content to wishlist (requires JWT)

### Like Routes
- `POST /api/like` - Like content (requires JWT)

### Comment Routes
- `GET /api/content/<content_id>/comments` - Get threaded comments for content (requires JWT)

### Share Routes
- `POST /api/share` - Share content with another user (requires JWT)

### Admin Routes
- `PATCH /api/admin/users/<user_id>/deactivate` - Deactivate a user (admin only)
- `POST /api/content/<content_id>/approve` - Approve content (admin only)

## Contributing
Contributions are welcome! Please fork the repository and submit pull requests for any enhancements or bug fixes.

## License
This project is licensed under the MIT License.
