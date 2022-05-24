# FastAPI Server

import base64

import json
import hashlib
import hmac
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "3994a6567f696ee6a1afab204908702e61d1b1548edeec67daec349cafb6a978"
PASSWORD_SALT = "a1ba088154fb663448492476fe8a21be2d8d87b4417533d852002ad3d353c3cb"

def sign_data(data:str) ->str:
    """Возвращаем подписанные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    print("username_base64", username_base64)
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT ).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash

users = {
    "lazarev":{
        "name" : "Алексей",
        "password" : "dfbd5067bfaeebcc8921e881a8b05262e5bd1f767fa806b787cfe965f99d3739",
        "balance":1000
    },
    "petrovich":{
        "name":"Пётр",
        "password":"7b068448fa2b93b2e1f0f64ca232128bfdb30afafeb39a5b1d0c0f2318ec3449",
        "balance":228
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("templates/login.html", "r") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")

    valid_username = get_username_from_signed_string(username)

    if not valid_username:
        response =  Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response =  Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    return Response(f"Привет, {users[valid_username]['name']}! <br/>"
    f"Баланс {users[valid_username]['balance']}", 
    media_type="text/html")



@app.post("/login")
def process_login_page(data: dict = Body(...)):
    print("data is ", data)
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    print("iser is ", user, "password is ", password)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps(
                {
                    "success": False,
                    "message": "Я вас не знаю!"
                
                }
            ),
            media_type = "application/json")

    response =  Response(
        json.dumps({
            "success": True,
            "message":  f"Добро пожаловать! {user['name']}!<br/>Баланс: {user['balance']} "
        }),
        media_type = "text/html")

    username_signed = base64.b64encode(username.encode()).decode()+"."+sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
