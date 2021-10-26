__header = """<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * data:; script-src 'none';">
    <title>Your ITSec Grades</title>
    <style>
      * { font-family: sans-serif; }
      body { margin: 2em auto; width: min(50vw, 20cm); }

      .col { display: flex; flex-direction: column; align-items: stretch; }
      .row { display: flex; align-items: center; justify-content: space-between; }
      .right { text-align: right; }
      .right-row { justify-content: flex-end; gap: 2px; }
      .sp-pre { margin-top: 2em; }
      .mono { font-family: monospace; }

      form.col > * { margin: 2px 0; }
      form.col > *:first-child { margin-top: 0; }

      .inline { display: inline; }

      .messages { color: #fff; background-color: #0056bd; text-align: center; font-weight: bold; padding: 2px 0; margin-bottom: 2em; width: 100%; }
      .messages > * { width: 100%; }
      .logo { color: #0056bd; text-align: center; font-weight: bold; margin: 0 auto 2em auto; width: max(10vw, 5cm); }
      .logo > img { margin-bottom: 0.5em; }
      .pfp { display: flex; align-items: flex-start; }
      .pfp > img { margin: 0; object-fit: contain; width: max(5vw, 2cm); height: max(5vw, 2cm); }
      .pfp > a { margin: 0 0 0 2px; font-size: x-small; }
      .grade { text-align: center; font-weight: bold; font-size: xxx-large; width: 100%; margin: 12px 0 0 0; }
      .flag { text-align: center; width: 100%; }
    </style>
  </head>
  <body>"""

__logo = """
    <div class="logo">
      <img src="data:image/svg+xml;base64,PHN2ZyB2ZXJzaW9uPSIxLjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDE1MCA2MCI+PHBhdGggZmlsbD0iIzAwNTZiZCIgZD0iTTAgNXY1aDEwdjQwSDB2MTBoMzBWNTBIMjBWMTBoMjB2NTBoMTBWMTBoMTB2MjVoMjB2MTVINjB2MTBoOTBWNTBoLTIwVjEwaDIwVjBIMHY1em05MCAxMi41VjI1SDcwVjEwaDIwdjcuNXpNMTIwIDMwdjIwaC0yMFYzNWgxMFYyNWgtMTBWMTBoMjB2MjB6Ii8+PC9zdmc+">
      Grade Overview
    </div>"""

__messages = """
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="messages">
        {% for message in messages %}
          <p>{{ message }}</p>
        {% endfor %}
        </div>
      {% endif %}
    {% endwith %}"""

__footer = """
  </body>
</html>"""

page = lambda content, logo=False: __header + (__logo if logo else "") + __messages + content + __footer

PROFILE_PAGE = page("""
    <div class="col">
      <div class="row">
        <div class="pfp">
          <img src="{{ data.picture }}">
        </div>
        <p class="right">{{ data.username }}<br><a href="/edit">Edit profile</a><br><a href="/logout">Log out</a></p>
      </div>
      <p class="grade">{{ data.grade }}</p>
      {% if flag %}
        <p class="flag">{{ flag }}</p>
      {% else %}
        <p class="flag">Sorry, your grade is not good enough to get a flag<br><a href="/complain">Make a complaint</a></p>
      {% endif %}
    </div>
""")

LOGIN_PAGE = page("""
    <form class="col" method="post">
      <input type="text" name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Log in</button>
    </form>
    <a href="/register">No account? Register now!</a>
""", logo=True)

REGISTER_PAGE = page("""
    <form class="col" method="post">
      <input type="text" name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Register</button>
    </form>
    <a href="/login">Already have an account? Log in here!</a>
""", logo=True)

COMPLAINT_PAGE = page("""
    <div class="col">
      <div class="row">
        <div class="pfp">
          <img src="{{ data.picture }}">
        </div>
        <p class="right">{{ data.username }}<br><a href="/edit">Edit profile</a><br><a href="/logout">Log out</a></p>
      </div>
      <form class="col sp-pre" method="post">
        <textarea name="complaint" placeholder="Please explain your complaint" required></textarea>
        <button type="submit">Submit complaint</button>
      </form>
    <div>
""")

EDIT_PAGE = page("""
    <form class="col" method="post">
      <input type="text" name="username" placeholder="Username" value="{{ data.username }}">
      <input type="password" name="password" placeholder="New password (or empty)">
      <input class="mono" type="text" name="picture" placeholder="Profile picture URL" value="{{ data.picture }}">
      <div class="row right-row">
        <form class="inline"><button type="submit">Cancel</button></form>
        <button type="submit">Change</button>
      </div>
    </form>
""")
