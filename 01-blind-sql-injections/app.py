from flask import Flask, request, redirect, session
from flask_session import Session
import datetime
import subprocess
import sqlite3
import os
import binascii

ADMIN_USER = "admin"

PAGE_HEAD = """
<!doctype html>
<html>
<head>
<title>TUM+!</title>
<style>
body {
    text-align: center;
}

h1 {
    font-family: sans-serif;
    color: #0065bd;
}
#results {
    margin-top: 10px;
    text-align: left;
}
</style>

</head>

<body>
    <h1>TUM+!</h1>
    <h2>The <i>excellent</i> social network!</h2>
"""

LOGIN_FORM = """
    <form action="/" method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="text" name="password" placeholder="Password">
        <input type="submit" value="Login">
    </form>
"""

PAGE_FOOTER = """
</body>
</html>
"""

app = Flask(__name__)

if not os.path.exists("app-secret.key"):
    with open("app-secret.key", "wb") as f:
        f.write(os.getrandom(32))

with open("app-secret.key", "rb") as f:
    app.secret_key = f.read()

app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=20)
app.config["SESSION_TYPE"] = "filesystem"
Session(app) # Stores sessions in current working directory, which is OK for us.


def load_db(db, admin_user, admin_pass):
    db.execute("CREATE TABLE tumoogleplus_users (id INT PRIMARY KEY, username TEXT, password TEXT)")
    db.execute("""INSERT INTO tumoogleplus_users VALUES (1, "{}", "{}")""".format(admin_user, admin_pass))


@app.route("/", methods=["POST", "GET"])
def index():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        admin_pass = session.get('admin_pass')
        if admin_pass is None:
            admin_pass = "435e8bfc7905d7e5c18fffd4ba4ea519" # don't use random password to run and macOS and be predictable
            session['admin_pass'] = admin_pass

        db = sqlite3.connect(":memory:", isolation_level=None)
        load_db(db, ADMIN_USER, admin_pass)
        cur = db.cursor()
        cur.execute("SELECT * FROM tumoogleplus_users WHERE username = '{}' and password='{}'".format(username, password))
        res = cur.fetchone()
        if res:
            if res[1] == username == ADMIN_USER and res[2] == password == admin_pass:
                flag = subprocess.check_output("/bin/flag").decode().strip()
                return PAGE_HEAD + "<b>Hi {}, here is your flag: {}</b>".format(username, flag) + PAGE_FOOTER
            else:
                return PAGE_HEAD + "<b>Hmm my database says you're admin, but of course I20 doesn't fall for your cheap tricks!!</b>" + PAGE_FOOTER
        else:
            return redirect("/")
    else:
        return PAGE_HEAD + LOGIN_FORM + PAGE_FOOTER
