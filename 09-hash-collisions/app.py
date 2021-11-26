from flask import Flask, request
import subprocess
import os

from parser import check_files

app = Flask(__name__)

page = """
<!doctype html>
<html>
<head>
<title>Fake your ITSec grade!</title>
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
<main style="max-width:800px; margin: 0px auto">
<h1>Fake your ITSec grade!</h1>

TUM uses its own proprietary format to store grades for students and uses signatures based on the MD5 hash of the file to attest to others that the grade file is unmodified. Can you change your ITSec grade from 5.0 to 1.0? Please provide me two grading files with the <b>same</b> MD5 hash!

<form enctype="multipart/form-data" action="/" method="post" style="margin: 20px auto">
<table>
<tr>
<td>File 1 (ITSec Grade 1.0)</td>
<td><input name="file1" type="file"></td>
</tr>
<tr>
<td>File 2 (ITSec Grade 5.0)</td>
<td><input name="file2" type="file"></td>
</tr>
</table>
<input type="submit" value="Upload!">
</form>
</main>
</body>
</html>"""

@app.route("/", methods=["GET", "POST"])
def index():
    # Handle upload
    if request.method == "POST":
        print(request.files)
        if not ("file1" in request.files and
            "file2" in request.files):
            return "No files :/"
        randname = os.getrandom(8).hex()
        n1 = f"/tmp/{randname}1"
        n2 = f"/tmp/{randname}2"
        request.files["file1"].save(n1)
        request.files["file2"].save(n2)

        success = check_files(n2, n1)

        os.remove(n1)
        os.remove(n2)

        if success:
            return subprocess.check_output("/bin/flag")
        else:
            return "Nope :( Try again!"

    return page
