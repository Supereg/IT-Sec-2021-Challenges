from flask import Flask, request
import subprocess
import sqlite3

app = Flask(__name__)

page_head = """
<!doctype html>
<html>
<head>
<title>TUMoogle!</title>
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
<div style="text-align: right"><a href="#">TUM+</a></div>
    <h1>TUMoogle!</h1>
    <h2>The <i>excellent</i> search engine!</h2>
    <form action="/" method="get">
        <input type="text" name="q">
        <input type="submit" value="Search!">
    </form>
<div id="results">"""

page_footer = """
</div>
</body>
</html>
"""

def load_internet(db):
    db.execute("CREATE TABLE internet_index (id INT PRIMARY KEY, title TEXT, url TEXT)")
    db.execute("""INSERT INTO internet_index VALUES
    (NULL, "Chair for IT Security", "http://www.sec.in.tum.de"),
    (NULL, "Technische Universität München (TUM)", "http://www.tum.de"),
    (NULL, "Heise", "http://www.heise.de"),
    (NULL, "Stack Overflow", "http://www.stackoverflow.com"),
    (NULL, "TUM Moodle", "http://moodle.tum.de"),
    (NULL, "TUM Online", "http://campus.tum.de"),
    (NULL, "Wikipedia", "http://www.wikipedia.de")
    """)

    db.execute("CREATE TABLE tumoogleplus_users (id INT PRIMARY KEY, username TEXT, password TEXT)")
    flag = subprocess.check_output("/bin/flag").decode()
    db.execute("""INSERT INTO tumoogleplus_users VALUES (1, "admin", "{}")""".format(flag))

@app.route("/")
def index():
    q = request.args.get("q")
    print(q)
    page = ""
    if q:
        if len(q) >= 3:
            db = sqlite3.connect(":memory:", isolation_level=None)
            load_internet(db)
            cur = db.cursor()
            cur.execute('SELECT * FROM internet_index WHERE title LIKE "%{}%"'.format(q))
            page += "<h2>Results</h2>"
            for record in cur.fetchall():
                page = page + """<a href="{}">{}</a><br>""".format(record[2], record[1])
        else:
            page = "Search query to short!"
    return page_head + page + page_footer
