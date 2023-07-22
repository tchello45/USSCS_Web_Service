from usscs import db_api
from usscs_enc import enc_db_api
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_socketio import SocketIO, send, emit, join_room, leave_room
import APIs_USSCS
import json
import APIs
import rsa
import os
import hashlib
import error
import eventlet
import threading
from jwt import (
    JWT,
    jwk_from_pem,
)


eventlet.monkey_patch()
if not os.path.isfile("public_key.pem") and not os.path.isfile("private_key.pem"):
    print("Generating keys...")
    (public_key, private_key) = rsa.newkeys(512)
    print("Keys generated.")   
    with open("public_key.pem", "wb") as f:
        f.write(public_key.save_pkcs1())
    with open("private_key.pem", "wb") as f:
        f.write(private_key.save_pkcs1())
    print("Keys saved.")
    print("Keys loaded.")
else:
    with open("public_key.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("private_key.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    print("Keys loaded.")
class tokens:
    @staticmethod
    def generate_token(username:str, password:str, API_id:int, login_password:str, enc:bool):
        return JWT().encode({"username":username, "password":password, "API_id":API_id, "login_password":login_password, "enc":enc}, 
                            jwk_from_pem(private_key.save_pkcs1()), alg="RS256")
    @staticmethod
    def decode_token(token:str):
        return JWT().decode(token, jwk_from_pem(public_key.save_pkcs1()))
    

app = Flask(__name__)
app.secret_key = "secret_key"
socketio = SocketIO(app)

@socketio.on("connect")
def connect():
    print("Connected")
@socketio.on("disconnect")
def disconnect():
    print("Disconnected")

@socketio.on("login")
def login(data):
    flag = 2
    username = data["username"]
    password = data["password"]
    API_server = data["API_server"]
    API_id = APIs.get_id(API_server)
    login_password = data["login_password"]
    if hashlib.sha256(login_password.encode()).hexdigest() != APIs.get_login_hash(APIs.get_id(API_server)):
        emit("status", error.gen_status_message(False, 402, flag, username, API_server, "Wrong login password"))
        return False
    enc = bool(APIs.get_enc(API_id))
    if enc:
        try:
            enc_db_api.user(username, password, path=f"DATABASE/APIs/{API_id}/")
            emit("status", error.gen_status_message(True, 200, flag, username, API_server, "User logged in"))
            emit("token", tokens.generate_token(username, password, API_id, login_password, enc))
            return True
        except ValueError as e:
            emit("status", error.gen_status_message(False, 400, flag, username, API_server, "Authentication failed"))
            return False
    else:
        try:
            db_api.user(username, password, path=f"DATABASE/APIs/{API_id}/")
            emit("status", error.gen_status_message(True, 200, flag, username, API_server, "User logged in"))
            emit("token", tokens.generate_token(username, password, API_id, login_password, enc))
            return True
        except ValueError as e:
            emit("status", error.gen_status_message(False, 400, flag, username, API_server, "Authentication failed"))
            return False
    
@socketio.on("register")
def register(data):
    flag = 3
    username = data["username"]
    password = data["password"]
    API_server = data["API_server"]
    register_password = data["register_password"]
    API_id = APIs.get_id(API_server)
    enc = APIs.get_enc(API_id)
    if hashlib.sha256(register_password.encode()).hexdigest() != APIs.get_registration_hash(API_id):
        emit("status", error.gen_status_message(False, 403, flag, username, API_server, "Wrong registration password"))
        return False
    if enc:
        pub = data["public_key"]
        priv = data["private_key"]
    else:
        try:
            db_api.add_user(username, password, path=f"DATABASE/APIs/{API_id}/")
            emit("status", error.gen_status_message(True, 201, flag, username, API_server, "User registered"))
            return True 
        except ValueError as e:
            emit("status", error.gen_status_message(False, 420, flag, username, API_server, "Username already exists"))
            return False

@socketio.on("token_check")
def token_check(data):
    flag = 9
    token = data["token"]
    try:
        data = tokens.decode_token(token)
    except Exception as e:
        emit("status", error.gen_status_message(False, 401, flag, "Unknown", "Unknown", "Token decode failed"))
        return False
    API_id = data["API_id"]
    username = data["username"]
    password = data["password"]
    login_password = data["login_password"]
    enc = data["enc"]
    if hashlib.sha256(login_password.encode()).hexdigest() != APIs.get_login_hash(API_id):
        emit("status", error.gen_status_message(False, 402, flag, username, APIs.get_client(API_id), "Wrong login password at token check"))
        return False
    if enc:
        try:
            enc_db_api.user(username, password, path=f"DATABASE/APIs/{API_id}/")
            emit("status", error.gen_status_message(True, 210, flag, username, APIs.get_client(API_id), "Token check passed"))
            return True
        except ValueError as e:
            emit("status", error.gen_status_message(False, 400, flag, username, APIs.get_client(API_id), "Authentication failed at token check"))
            return False
    else:
        try:
            db_api.user(username, password, path=f"DATABASE/APIs/{API_id}/")
            emit("status", error.gen_status_message(True, 210, flag, username, APIs.get_client(API_id), "Token check passed"))
            return True
        except ValueError as e:
            emit("status", error.gen_status_message(False, 400, flag, username, APIs.get_client(API_id), "Authentication failed at token check"))
            return False
    
@socketio.on("send_message")
def send_message(data_):
    token = data_["token"]
    flag = 0
    try:
        data = tokens.decode_token(token)
    except Exception as e:
        emit("status", error.gen_status_message(False, 401, flag, "Unknown", "Unknown", "Token decode failed"))
        return False
    API_id = data["API_id"]
    username = data["username"]
    password = data["password"]
    login_password = data["login_password"]
    enc = data["enc"]
    if hashlib.sha256(login_password.encode()).hexdigest() != APIs.get_login_hash(API_id):
        emit("status", error.gen_status_message(False, 402, flag, username, APIs.get_client(API_id), "Wrong login password at send message"))
        return False
    if enc:
        try:
           user =  enc_db_api.user(username, password, path=f"DATABASE/APIs/{API_id}/")
        except ValueError as e:
            emit("status", error.gen_status_message(False, 400, flag, username, APIs.get_client(API_id), "Authentication failed at send message"))
            return False
    else:
        try:
            user = db_api.user(username, password, path=f"DATABASE/APIs/{API_id}/")
        except ValueError as e:
            emit("status", error.gen_status_message(False, 400, flag, username, APIs.get_client(API_id), "Authentication failed at send message"))
            return False
    target = data_["target"]
    message = data_["message"]
    try:
        user.send_message(target, message)
        emit("status", error.gen_status_message(True, 202, flag, username, APIs.get_client(API_id), "Message sent"))
        return True
    except ValueError as e:
        emit("status", error.gen_status_message(False, 410, flag, username, APIs.get_client(API_id), "Target not found"))
        return False

@socketio.on("get_enc_API_server")
def get_enc_API_Server(data):
    API_server = data["API_server"]
    try:
        API_id = APIs.get_id(API_server)
    except Exception as e:
        emit("status", error.gen_status_message(False, 404, 0, "Unknown", "Unknown", "API Server not found"))
        return False
    enc = bool(APIs.get_enc(API_id))
    emit("enc", enc)

@socketio.on("login_register_password_check")
def login_register_password_check(data):
    flag = 9
    API_server = data["API_server"]
    API_id = APIs.get_id(API_server)
    login_password = data["login_password"]
    register_password = data["register_password"]
    if hashlib.sha256(login_password.encode()).hexdigest() != APIs.get_login_hash(API_id):
        emit("status", error.gen_status_message(False, 402, flag, "Unknown", "Unknown", "Wrong login password at login register password check"))
        return False
    if hashlib.sha256(register_password.encode()).hexdigest() != APIs.get_registration_hash(API_id):
        emit("status", error.gen_status_message(False, 403, flag, "Unknown", "Unknown", "Wrong registration password at login register password check"))
        return False
    emit("status", error.gen_status_message(True, 211, flag, "Unknown", "Unknown", "Password check passed"))
    return True
if __name__ == '__main__':
    os.system("clear")
    print("__________SERVER__________")
    socketio.run(app, host='0.0.0.0', port=5000)