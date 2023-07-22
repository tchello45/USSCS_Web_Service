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
import jwt


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
    def generate_token(username:str, password:str, API_id:int, login_password:str):
        return jwt.encode({"username":username, "password":password}, private_key.save_pkcs1(), algorithm="RS256")
    @staticmethod
    def decode_token(token:str):
        return jwt.decode(token, public_key.save_pkcs1(), algorithms="RS256")
    

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
    username = data["username"]
    password = data["password"]
    API_server = data["API_server"]
    login_password = data["login_password"]
    enc = APIs.get_enc(APIs.get_id(API_server))
    print(enc)

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

if __name__ == '__main__':
    os.system("clear")
    print("__________SERVER__________")
    socketio.run(app, host='0.0.0.0', port=5000)