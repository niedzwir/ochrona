import logging
import os
import json
import hashlib
import pymysql
import bcrypt
import re
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time
import math
from datetime import date
from flask import Flask, render_template, abort
from flask import request, jsonify, redirect, url_for, make_response, abort,session
from flask import flash, send_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, set_access_cookies, get_jwt_identity
from flask_jwt_extended import create_refresh_token, set_refresh_cookies,jwt_refresh_token_required,unset_access_cookies,unset_refresh_cookies

SECRET_KEY = "LOGIN_JWT_SECRET"
TOKEN_TIME = 10*60 #powinno być krócej, za to z refreshowaniem
app = Flask(__name__, static_url_path="")
app.secret_key = SECRET_KEY
app.config["JWT_TOKEN_LOCATION"] = 'cookies'
SESSION_ID = 'session_id'
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

derp = 0

db_config = {
            "user": "root",
            "password": "H*Xhz{2T\"4>jT8vJ",
            "host": "mysql-db",
            "db": "data",
            "charset": "utf8mb4",
            "cursorclass": pymysql.cursors.DictCursor,
            "autocommit": False
        }
connection = pymysql.connect(**db_config)
cursor = connection.cursor()

jwt = JWTManager(app)

log = app.logger

@app.route("/registration", methods=["GET"])
def registration():
    template = make_response(render_template("registration.html"))
    unset_access_cookies(template)
    unset_refresh_cookies(template)
    session.clear()
    flash("derp")
    return template

@app.route("/register/", methods=["GET", "POST"])
def register():
    log.debug("register")
    login = request.form["login"]
    password = request.form["password"]
    password = bytes(password, 'utf-8')
    mail = request.form["mail"]
    #https://www.hacksplaining.com/prevention/sql-injection
    if(login.isalpha() == False):
        abort(400,"invalid login")
    #https://www.geeksforgeeks.org/check-if-email-address-valid-or-not-in-python/
    #https://stackoverflow.com/questions/201323/how-to-validate-an-email-address-using-a-regular-expression
    regex = '''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''
    if(re.search(regex,mail) == None): 
        abort(400,"invalid mail")
    mail = mail.replace('\'','')
    #http://zetcode.com/python/bcrypt/
    #https://crackstation.net/hashing-security.htm
    #https://en.wikipedia.org/wiki/Bcrypt
    salt = bcrypt.gensalt(rounds=8)
    hashed = bcrypt.hashpw(password, salt)
    cursor.execute(''' select * from users where login = %(login)s''',{"login":login})
    response = cursor.fetchall()
    if(cursor.rowcount == 0): 
        # cursor.execute(''' insert into users(login,password,mail) values ('derp3', 'aaaaaa','aaa' ) ''')
        # connection.commit()
        cursor.execute('''insert into users(login,password,mail) values (%(login)s, %(hashed)s, %(mail)s)''',{"login":login,'hashed':hashed,"mail":mail})
        connection.commit()
    else:
        abort(400,"login zajęty")
    e = "entropia twojego hasła: " + str(entropy(password))
    flash(e)
    return render_template("registration.html", e = e)

@app.route("/login", methods=["GET"])
def login():
    template = make_response(render_template("login.html"))
    unset_access_cookies(template)
    unset_refresh_cookies(template)
    session.clear()
    return template

@app.route("/logme", methods=["POST"])
def logme():
    time.sleep(2)
    if(check_fails() > 5):
        abort(403,"masz bana za zbyt dużą ilość błędych logowań, wróć jutro")
    form = request.form.to_dict()
    login = form["login"]
    if(login.isalpha() == False):
        fail()
        abort(404,"invalid login")
    password = form["password"]
    cursor.execute(''' select * from users where login = %(login)s''',{"login":login})
    record = cursor.fetchall()
    if(cursor.rowcount == 0):
        fail()
        abort(404,"nie ma takiego użytkownika")

    hash = record[0].get("password")
    
        
    if bcrypt.checkpw(password.encode('utf8'), hash.encode('utf8')):
        access_token = create_access_token(identity=login)
        response = make_response(render_template("securepage.html", user = login))
        response.set_cookie(SESSION_ID, login, max_age=TOKEN_TIME, httponly=True)
        set_access_cookies(response, access_token)
        refresh_token = create_refresh_token(identity=login)
        set_refresh_cookies(response, refresh_token)
        return response
    else:
        fail()
        abort(400, "złe hasło")


def check_fails():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = date.today()
    cursor.execute('''select * from  fails where ip = %(ip)s and datediff(fail_date,%(now)s) < 1''',{"ip":ip,"now":now})
    return cursor.rowcount

def fail():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = date.today()
    cursor.execute('''insert into fails(ip, fail_date) values (%(ip)s, %(date)s)''',{"ip":ip,'date':now})
    connection.commit()

@app.route("/securepage", methods=["GET"])
@jwt_required
def securepage():
    current_user = get_jwt_identity()
    return render_template("securepage.html", user = current_user)

@app.route("/note", methods=["POST"])
@jwt_required
def note():
    form = request.form.to_dict()
    note_text = form["note_text"].replace('\'','波兰')
    if(len(note_text)>8000):
        abort(400, "notatka może mieć maksymalnie 8000 znaków")
    note_name = form["note_name"]
    if(note_name.isalpha() == False):
        abort(400,"nie umiesz czytać? nazwa notatki może mieć tylko litery!")
    cursor.execute(''' select * from notes where note_name = %(note_name)s''',{"note_name":note_name})
    response = cursor.fetchall()
    if(cursor.rowcount != 0):
        abort(400,"ta nazwa notatki jest już zajęta :(")
    login = get_jwt_identity()
    cursor.execute(''' select * from users where login = %(login)s''',{"login":login})
    response = cursor.fetchall()
    id = response[0].get("id")

    note_text = '\n'.join(note_text[i:i+40] for i in range(0, len(note_text), 40)) 
    cursor.execute('''insert into notes(user_id,note_name,note,public) values (%(user_id)s,%(name)s, %(note_text)s, %(public)s)''',{"user_id":id,'name':note_name,'note_text':note_text,"public":False})
    connection.commit()

    return render_template("securepage.html", user = login)

@app.route("/readnote", methods=["GET", "POST"])
@jwt_required
def readnote():
    form = request.form.to_dict()
    current_user = get_jwt_identity()
    cursor.execute(''' select * from users where login = %(login)s''',{"login":current_user})
    response = cursor.fetchall()
    id = response[0].get("id")

    note_name = form["note_name"].replace('\'','波兰')
    cursor.execute(''' select * from notes where note_name = %(note_name)s''',{"note_name":note_name})
    response = cursor.fetchall()
    if(cursor.rowcount == 0):
        abort(404, "ta notatka nie istnieje")
    log.debug(response[0].get("user_id"))
    if(int(response[0].get("user_id")) != int(id) and response[0].get("public") == False):
        abort(403, "nie masz dostępu do tej notatki")
    
    note = response[0].get("note")
    return render_template("note.html", note = note.replace("波兰","\'"), note_name = note_name.replace("波兰","\'"))

@app.route("/encrypted_note", methods=["POST"])
@jwt_required
def encrypted_note():
    form = request.form.to_dict()
    login = get_jwt_identity()  
    note_name = form["note_name"]
    password = form["password"]
    note_text = form["note_text"]
    
    salt = b"saltysalt"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=1000)
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password,"utf-8")))
    f = Fernet(key)
    note_text = f.encrypt(note_text.encode())

    if(len(note_text)>8000):
        abort(400, "notatka może mieć maksymalnie 8000 znaków")
    if(note_name.isalpha() == False):
        abort(400,"nie umiesz czytać? nazwa notatki może mieć tylko litery!")
    cursor.execute(''' select * from encrypted_notes where note_name = %(note_name)s''',{"note_name":note_name})
    response = cursor.fetchall()
    if(cursor.rowcount != 0):
        abort(400,"ta nazwa notatki jest już zajęta :(")
    
    salt = bcrypt.gensalt(rounds=8)
    password = bytes(password, 'utf-8')
    hash = bcrypt.hashpw(password, salt)

    #note_text = '\n'.join(note_text[i:i+40] for i in range(0, len(note_text), 40)) 
    cursor.execute('''insert into encrypted_notes(note_name,note,password) values (%(name)s, %(note_text)s, %(password)s)''',{"user_id":id,'name':note_name,'note_text':note_text,"password":hash})
    connection.commit()

    return render_template("securepage.html", user = login)


@app.route("/readencryptednote", methods=["GET", "POST"])
@jwt_required
def readencryptednote():
    form = request.form.to_dict()
    note_name = form["note_name"].replace('\'','波兰')
    cursor.execute(''' select * from encrypted_notes where note_name = %(note_name)s''',{"note_name":note_name})
    response = cursor.fetchall()
    if(cursor.rowcount == 0):
        abort(404, "ta notatka nie istnieje")
    hash = response[0].get("password")
    password = form["password"]
    if bcrypt.checkpw(password.encode('utf8'), hash.encode('utf8')):
        note = response[0].get("note")
    else:
        abort(400,"złe hasło")
    salt = b"saltysalt"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=1000)
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password,"utf-8")))
    f = Fernet(key)
    note = f.decrypt(note.encode())
    note = note.decode()
    note = '\n'.join(note[i:i+40] for i in range(0, len(note), 40))
    return render_template("note.html", note = note, note_name = note_name.replace("波兰","\'"))
@app.route("/", methods=["GET"])
def home():
    response = make_response(render_template("home.html"))
    unset_access_cookies(response)
    unset_refresh_cookies(response)
    session.clear()
    return response

def entropy(password):
    stat = {}
    for c in password:
        m = c
        if m in stat:
            stat[m] += 1
        else:
            stat[m] = 1
        H = 0.0
        for i in stat.keys():
            pi = stat[i]/len(password)
            H -= pi*math.log2(pi)
    return H
@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html", error=error)

@app.errorhandler(401)
def page_unauthorized(error):
    return render_template("401.html", error=error)

@app.errorhandler(400)
def wrond_demand(error):
    return render_template("400.html", error=error)

@app.errorhandler(403)
def you_cant_do_that(error):
    return render_template("403.html", error=error)

@app.errorhandler(500)
def something_went_wrong(error):
    return render_template("500.html", error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)