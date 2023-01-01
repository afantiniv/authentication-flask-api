"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""

from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, TokenBlocklist
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt


api = Blueprint('api', __name__)

bcrypt = Bcrypt(Flask(__name__))

#Inicio de sesion
@api.route('/login', methods = ['POST'])
def user_login():
    email = request.json.get('email')
    password = request.json.get('password')
    user = User.query.filter(User.email == email).first()
    if user is None:
        return jsonify({"msg": "Bad email or password"}), 401    

    #if user.password == password:
    if bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity = user.id)
        refresh_token = create_refresh_token(identity = user.id)
        return jsonify({"token": access_token, "refresh": refresh_token,  "user.id": user.id}),200
    

@api.route('/updatepassword', methods = ['PATCH'])
@jwt_required()
def patch_user_pass():
    new_password = request.json.get('password')
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "Clave actualizada"}), 200


@api.route('/signup', methods = ['POST'])
def create_user():
    email = request.json.get('email')
    password = request.json.get('password')
    user = User(email = email, password = bcrypt.generate_password_hash(password).decode("utf-8"),is_active = True)
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "Usuario registrado!"}), 200

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route("/logout", methods=["DELETE"])
@jwt_required()
def modify_token():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg="JWT revoked")


