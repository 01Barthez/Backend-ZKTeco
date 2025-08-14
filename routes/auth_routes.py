from flask import Blueprint, request, jsonify
from models.user import User
from services.auth import generate_token
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.warning("Username or password missing")
        return jsonify({"msg": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        logger.warning(f"Invalid login for username: {username}")
        return jsonify({"msg": "Invalid credentials"}), 401
    print(f"[DEBUG] Before generate_token: user.id={user.id} (type: {type(user.id)})")
    try:
        access_token = generate_token(user.id)
        logger.info(f"Token generated for user id {user.id}")
    except Exception as e:
        logger.error(f"Token generation error: {e}", exc_info=True)
        return jsonify({"msg": "Token generation failed"}), 500

    return jsonify(access_token=access_token)


@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    identity_str = get_jwt_identity()
    logger.debug(f"Token identity: {identity_str}")

    try:
        user_id = int(identity_str)
    except Exception:
        logger.error(f"Invalid identity: {identity_str}")
        return jsonify({"msg": "Invalid user identity"}), 400

    logger.info(f"Access granted for user {user_id}")
    return jsonify(message=f"Access granted for user ID {user_id}")

