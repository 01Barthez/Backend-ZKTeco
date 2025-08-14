import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'change_me_to_a_strong_secret')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:12032004@localhost:5432/zkteco_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'change_me_to_another_secret')
    JWT_ACCESS_TOKEN_EXPIRES = seconds=3600

