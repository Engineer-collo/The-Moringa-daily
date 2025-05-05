import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'moringa.db')}"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = '4bfbece877bc4c6a9276b4f9f0203a45d722bbfd02728c7d823438120c8b5c91'
JWT_SECRET_KEY = 'd9cbf61a59b0c1e24e9fc62547c3d524c97a35d7e283c902835de5d61b126bde'
JWT_ACCESS_TOKEN_EXPIRES = 864000  