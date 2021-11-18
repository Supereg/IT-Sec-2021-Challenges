#!/usr/bin/env python3

from Crypto.Cipher import AES
from flask import Flask, redirect, render_template_string, request

import base64
import bcrypt
import collections
import json
import os
import subprocess

app = Flask(__name__)

# App metadata
if not os.path.exists('app-secret.key'):
    with open('app-secret.key', 'wb') as f:
        f.write(os.urandom(32))

with open('app-secret.key', 'rb') as f:
    SECRET_KEY = f.read()

NONCE_LENGTH = 12 # bytes (of the 16 byte IV, the rest is a automatically generated counter)

COOKIE_NAME = 'session'
COOKIE_LIFETIME = 3600 # seconds

User = collections.namedtuple('User', ('password_hash', 'command'))
USER_DB = {
    'admin':    User(b'$2b$12$RHOf472SiDS1rXo6mdUW6.B4Aww7f94kDaL9nNnzkIjTXqFntdJLa', '/bin/flag'),
    'testuser': User(b'$2b$12$o5BG0DdXVxkZoNickA4aBeiRsKnWq.i1.9S1GCC77jkLAWTcH0ycm', '/bin/date'),
}

# Session management
def load_session(request):
    # Get raw cookie
    raw_cookie = request.cookies.get(COOKIE_NAME)
    if not raw_cookie:
        return None
    # Decrypt and load cookie
    try:
        data = base64.b64decode(raw_cookie)
        nonce, ciphertext = data[:NONCE_LENGTH], data[NONCE_LENGTH:]
        plaintext = AES.new(SECRET_KEY, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)
        return json.loads(plaintext.decode())
    except:
        import traceback
        traceback.print_exc()
        return None

def delete_session_on(response):
    response.set_cookie(COOKIE_NAME, '', expires=0)
    return response

def add_session_on(response, session_data):
    nonce = os.urandom(NONCE_LENGTH)
    plaintext = json.dumps(session_data).encode()
    ciphertext = AES.new(SECRET_KEY, AES.MODE_CTR, nonce=nonce).encrypt(plaintext)
    raw_cookie = base64.b64encode(nonce + ciphertext)
    response.set_cookie(COOKIE_NAME, raw_cookie, max_age=COOKIE_LIFETIME)
    return response

# Routes
@app.route('/', methods=['GET'])
def index():
    session = load_session(request)
    if not session:
        return redirect('/login')
    user = session['user']
    return render_template_string(MAIN_SITE, user = user, output = subprocess.check_output([USER_DB[user].command]).decode().strip())

@app.route("/logout")
def logout():
    response = redirect('/login')
    if load_session(request):
        response = delete_session_on(response)
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if load_session(request):
        return redirect('/')
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        if not username or not password or not username in USER_DB or not bcrypt.checkpw(password.encode(), USER_DB[username].password_hash):
            return render_template_string(LOGIN_SCREEN, warning = 'Invalid username or password')
        session_data = {
            'user': username,
            # Add any additional session data here
        }
        return add_session_on(redirect('/'), session_data)
    return render_template_string(LOGIN_SCREEN, warning = '')

# Raw site data
def remove_leading_line(text):
    return text.split('\n', 1)[-1]

HEADER = remove_leading_line('''
<!DOCTYPE html>
<html>
  <head>
    <title>TUMtime</title>
  </head>
  <body>
''')

FOOTER = remove_leading_line('''
  </body>
</html>
''')

MAIN_SITE = HEADER + remove_leading_line('''
    <h1>TUMtime <small><small>by I20</small></small></h1>
    <p>Welcome back, {{ user }}</p>
    <p>It is now <b>{{ output }}</b></p>
''') + FOOTER

LOGIN_SCREEN = HEADER + remove_leading_line('''
    <h1>TUMtime <small><small>by I20</small></small></h1>
    <form method="POST" action="/login">
        <label for="username">Username: </label><input type="text" name="username" placeholder="Username"><br>
        <label for="password">Password: </label><input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Log in">
    </form>
    <span style="color: red;">{{ warning }}</span>
    <p><small>To test TUMtime, log in with username <code>testuser</code> and password <code>foobar</code></small></p>
''') + FOOTER
