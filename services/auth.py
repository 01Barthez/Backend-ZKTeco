from flask_jwt_extended import create_access_token
from datetime import timedelta

def generate_token(identity):
    print(f"[DEBUG] generate_token called with identity={identity} (type: {type(identity)})")
    return create_access_token(identity=str(identity))
