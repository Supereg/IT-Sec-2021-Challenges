const express = require('express')
const bcrypt = require('bcrypt')
const sqlite = require('sqlite3')
const fs = require('fs');
const nodemailer = require("nodemailer");
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const net = require('net');

const auth = require('./auth');
const util = require('./util');
const flags = require('./flags');

const UPLOAD_DIR = path.join(__dirname, 'uploads');

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR
    // By default, we get a random file name
  }),
  limits: {
    fileSize: 10240
  }
});

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_SERVER,
  port: process.env.SMTP_PORT || 25,
  secure: process.env.SMTP_USE_TLS === "true",
  auth: process.env.SMTP_USER && process.env.SMTP_PASSWORD ? {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  } : undefined,
});

const db = new sqlite.Database(':memory:');

const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use('/static', express.static(path.join(__dirname, 'static')));

const port = 3000
const flagCourseId = crypto.randomInt(2 ** 48 - 1);

// Set up database
db.serialize(() => {
  db.run("PRAGMA foreign_keys = on");

  // Set up users
  db.run("CREATE TABLE users (email TEXT PRIMARY KEY NOT NULL, password TEXT, role TEXT, profile TEXT)");
  db.run("INSERT INTO users VALUES ('fabian@cool.invalid', '$2b$10$y/uCIneTi52Kz/D3Z9Qn9OyI9e8rt4whEwqS0VByKceFZofKnrPlS', ?, 'how do you do, fellow students')", auth.USER_ROLE);

  let adminPassword = fs.readFileSync(path.join(__dirname, 'admin-password.txt'), { encoding: 'utf-8' });
  let hash = bcrypt.hashSync(adminPassword, bcrypt.genSaltSync(10));
  db.run("INSERT INTO users VALUES ('uebungsleiter@itsec.sec.in.tum.de', ?, ?, 'Tutor Tool Supervisor')", hash, auth.SUPERVISOR_ROLE);

  // Applications
  db.run("CREATE TABLE cvs (email TEXT PRIMARY KEY NOT NULL REFERENCES users(email) ON DELETE CASCADE, filename TEXT, storage_path TEXT)");
  db.run("CREATE TABLE applications (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT REFERENCES users(email) ON DELETE CASCADE, course TEXT REFERENCES courses(id) ON DELETE CASCADE, grade TEXT, application TEXT)");

  // Courses
  db.run("CREATE TABLE courses (id TEXT PRIMARY KEY NOT NULL, name TEXT, requirements TEXT, owner TEXT, active BOOLEAN NOT NULL CHECK (active  IN (0, 1)))");
  db.run("INSERT INTO courses VALUES ('IN0042', 'IT Security', 'Must be very 1337', 'uebungsleiter@itsec.sec.in.tum.de', 1)");
  db.run("INSERT INTO courses VALUES ('IN" + flagCourseId + "', 'Flag Course', 'Must have flag{12345}', 'in1338@itsec.sec.in.tum.de', 0)");
})

// Regularly clean up old CV entries (we drop them from the file system after some time)
setInterval(() => {
    db.all("SELECT * FROM cvs", (err, rows) => {
      if (err) {
        console.error('Error in cleanup task:', err);
        return;
      }
      if (!rows)
        return;
      let deleted = rows.map(row => row['storage_path']).filter(name => !fs.existsSync(path.join(UPLOAD_DIR, name)));
      let placeholders = deleted.map(_ => '?').join(', '); // Apparently there's no better way to do this?
      db.run("DELETE FROM cvs WHERE storage_path IN (" + placeholders + ");", deleted, (err) => {
        if (err)
          console.error('Error in cleanup task:', err);
      });
    });
  },
  60 * 1000 // 1min
);

function internalError(res, message) {
  console.error("[ERROR] " + message);
  return res.status(500).json({status: "error", error: message});
}
function userError(res, message) {
  return res.json({status: "error", error: message});
}

// USER MANAGEMENT
//  - POST /api/login:      Log in
//  - POST /api/register:   Register a new user
//  - POST /api/resetpw:    Reset password
//  - GET  /api/users:      List all users (admin only)
//  - GET  /api/user:       Get user details (admin only)
//  - POST /api/my-profile: Set your profile
//  - GET  /api/my-profile: Get your profile (some people hide a flag here!)

app.post("/api/login", (req, res) => {
  if (!req.body.email || !req.body.password)
    return userError(res, "No user or password specified");
  db.get("SELECT * FROM users WHERE email=?", req.body.email, (err, data) => {
    if (err) {
      return internalError(res, err);
    }
    if (data === undefined) {
      return userError(res, "This user does not exist");
    }

    bcrypt.compare(req.body.password, data["password"], (err, result) => {
      if (err) {
        return internalError(res, err);
      }
      if (result !== true) {
        return userError(res, "Incorrect password");
      }
      res.json({
        status: "success",
        token: auth.generateToken({
          sub: data["email"],
          auth: data["role"]
        })
      });
    });
  });
});

app.post("/api/register", (req, res) => {
  if (!req.body.email || !req.body.password)
    return userError(res, "No user or password specified");
  if (!/@/.test(req.body.email) || /@.*@/.test(req.body.email))
    return userError(res, "Invalid email address");
  if (!/@(sec\.in\.|in\.)?tum\.de$/.test(req.body.email))
    return userError(res, "Not a valid @tum.de or @in.tum.de email address");
  db.get("SELECT * FROM users WHERE email=?", req.body.email, (err, data) => {
    if (err) {
      return internalError(res, err);
    }
    if (data !== undefined) {
      return userError(res, "This user already exists");
    }
    bcrypt.genSalt(10)
      .then(salt => bcrypt.hash(req.body.password, salt))
      .then(hash => {
      db.run("INSERT INTO users (email, password, role, profile) VALUES (?, ?, ?, ?)", [req.body.email, hash, auth.USER_ROLE, JSON.stringify(util.pickAttrs(req.body, ["firstname", "lastname", "email"]))], err => {
        if (err) {
          return internalError(res, err);
        }
        res.json({
          status: "success"
        });
      });
    });
  });
});

app.post("/api/resetpw", (req, res) => {
  if (!req.body.email)
    return userError(res, "No user specified");
  db.get("SELECT * FROM users WHERE email=?", req.body.email, (err, data) => {
    if (err) {
      return internalError(res, err);
    }
    if (data === undefined) {
      return userError(res, "This user does not exist");
    }
    if (data["role"] !== auth.USER_ROLE) {
      return userError(res, "Please contact support directly to reset your password");
    }

    let newPassword = Math.random().toString(36).slice(-10);
    bcrypt.genSalt(10)
      .then(salt => bcrypt.hash(newPassword, salt))
      .then(hash => {
      db.run("UPDATE users SET password=? WHERE email=?", [hash, req.body.email], err => {
        if (err) {
          return internalError(res, err);
        }

        mailer.sendMail({
          from: process.env.SMTP_MAIL_FROM || "broken-tutor-tool@domain.invalid",
          to: req.body.email,
          subject: "Password reset for Broken Tutor Tool",
          text: `Your password for the Broken Tutor Tool has been reset.\n\nYour new password is: ${newPassword}\n`,
        }, (err) => {
          if (err) {
            return internalError(res, err);
          }

          res.json({
            status: "success",
          });
        });
      });
    });
  });
});

app.get("/api/users", (req, res) => {
  if (auth.requireAuth(req, res, roles=auth.ADMIN_ROLE)) {
    db.all("SELECT * FROM users", [], (err, rows) => {
      if (err) {
        return internalError(res, err);
      }

      res.json({
        status: "success",
        users: rows.map(o => util.pickAttrs(o, ["email", "role"])),
      });
    });
  }
});

app.get("/api/user", (req, res) => {
  if (!req.body.email) {
    return userError(res, "No user specified");
  }
  if (auth.requireAuth(req, res, roles=auth.ADMIN_ROLE, bypassUsers=req.query.email)) {
    db.get("SELECT * FROM users WHERE email=?", [req.query.email], (err, row) => {
      if (err) {
        return internalError(res, err);
      }
      if (row === undefined) {
        return userError(res, "This user does not exist");
      }
      res.json({
        status: "success",
        user: util.pickAttrs(row, ["email", "role"]),
      });
    });
  }
});

app.post("/api/my-profile", (req, res) => {
  if (!req.body.profile)
    return userError(res, "No profile content specified");
  const userData = auth.requireAuth(req, res);
  if (!userData)
    return;
  const { sub } = userData;
  db.get("UPDATE users SET profile=? WHERE email=?", [req.body.profile, sub], (err) => {
    if (err) {
      return internalError(res, err);
    }
    res.json({
      status: "success",
    });
  });
});

app.get("/api/my-profile", (req, res) => {
  const userData = auth.requireAuth(req, res);
  if (!userData)
    return;
  const { sub } = userData;
  const flag = flags.getUserFlag(sub);
  if (flag !== undefined) {
    res.json({
      status: "success",
      profile: JSON.stringify({flag: flag})
    });
    return;
  }
  db.get("SELECT profile FROM users WHERE email=?", [sub], (err, data) => {
    if (err) {
      return internalError(res, err);
    }
    if (data === undefined) {
      return userError(res, "This user does not exist");
    }
    res.json({
      status: "success",
      profile: data["profile"]
    });
  });
});


// COURSES
//  - GET  /api/courses:      List courses
//  - GET  /api/course:       Get info about a specific course
//  - GET  /api/applications: List applications for your courses (course owner only) - POST /api/apply:        Apply to become a tutor
//  - GET  /api/application/:id: Get info about a submitted application
app.get("/api/courses", (req, res) => {
  if (!auth.requireAuth(req, res)) return;
  db.all("SELECT * FROM courses", (err, rows) => {
    if (err) {
      return internalError(res, err);
    }
    res.json({
      status: "success",
      courses: rows.map(o => util.pickAttrs(o, ["id", "name", "active"]))
    });
  });
});
app.get("/api/course/:id", (req, res) => {
  if (!auth.requireAuth(req, res)) return;
  db.get("SELECT * FROM courses where id=?", [req.params.id], (err, row) => {
    if (err) {
      return internalError(res, err);
    }
    if (row === undefined) {
      return userError(res, "This course does not exist");
    }
    if (req.params.id === ("IN" + flagCourseId)) {
        row.requirements = "Must have acquired: " + flags.getCourseFlag();
    }
    res.json({
      status: "success",
      course: util.pickAttrs(row, ["id", "name", "requirements"])
    });
  });
});
app.get("/api/applications", (req, res) => {
  const userData = auth.requireAuth(req, res, [auth.SUPERVISOR_ROLE, auth.ADMIN_ROLE]);
  if (!userData) return;
  const { sub } = userData;

  db.all("SELECT a.email AS email, a.course AS course, c.name AS course_name, a.grade as grade, a.application AS application FROM applications a JOIN courses c ON c.id = a.course WHERE c.owner = ?", [sub], (err, rows) => {
    if (err) {
      return internalError(res, err);
    }
    rows.sort((a, b) => (a.course.localeCompare(b.course) || a.email.localeCompare(b.email)));
    res.json({
      status: "success",
      applications: rows
    });
  });
});
app.get("/api/application/:id", (req, res) => {
  const userData = auth.requireAuth(req, res, [auth.SUPERVISOR_ROLE, auth.ADMIN_ROLE]);
  if (!userData) return;
  const { sub } = userData;

  db.get("SELECT a.email AS email, a.course AS course, c.name AS course_name, a.grade as grade, a.application AS application FROM applications a JOIN courses c ON c.id = a.course WHERE c.owner = ? AND a.id = ?", [sub, req.params.id], (err, row) => {
    if (err) {
      return internalError(res, err);
    }
    res.json({
      status: "success",
      application: row
    });
  });
});

// YOUR APPLICATIONS
//  - POST /api/apply: Apply to become a tutor
//  - GET /api/cv:     Download your current CV
//  - PUT /api/cv:     Upload your CV
app.post("/api/apply", (req, res) => {
  const userData = auth.requireAuth(req, res);
  if (!userData) return;
  const { sub, auth: role } = userData;

  // Only normal users get to be tutors, it doesn't make sense for admins and supervisors to apply.
  if (role !== auth.USER_ROLE)
    return userError(res, "You cannot apply to be a tutor");

  // Validate parameters
  const { courseId, cvToken, grade, applicationText } = req.body;
  if (courseId === undefined)
    return userError(res, "No course ID specified in application");
  if (cvToken === undefined) // You can get the CV token via /api/cv - same as for /api/download!
    return userError(res, "No CV token specified");
  if (grade === undefined)
    return userError(res, "No grade specified");
  if (applicationText === undefined)
    return userError(res, "No application text specified");

  // Ensure the user uploaded their CV first!
  const result = auth.validateToken(cvToken);
  if (!result.valid)
    return userError(res, "No valid CV present");

  // Check the course exists
  db.get("SELECT * FROM courses WHERE id=? LIMIT 1", courseId, (err, data) => {
    if (err) {
      return internalError(res, err);
    }
    if (data === undefined) {
      return userError(res, "No such course");
    }
    // Store the application
    db.run("INSERT INTO applications (email, course, grade, application) VALUES (?, ?, ?, ?)", [sub, courseId, grade, applicationText], (err) => {
      if (err) {
        return internalError(res, err);
      }

      // this.lastID not set ???
      db.get("SELECT id FROM applications WHERE email = (?) ORDER BY id DESC LIMIT 1", [sub], (err, row) => {
        if (err) {
          return internalError(res, err);
        }

        // Send to course owner to check the application!
        if (!process.env.SUPERVISOR_CONTACT_PORT || !process.env.SUPERVISOR_CONTACT_HOST) {
          return userError(res, "Tried to send to supervisor, but wasn't configured");
        } else {
          let client = new net.Socket();
          client.connect(process.env.SUPERVISOR_CONTACT_PORT, process.env.SUPERVISOR_CONTACT_HOST, () => {
            client.write(row.id + "\n", "utf8", () => { client.destroy(); });
          });
        }
      });

      res.json({status: "success"});
    });
  });
});

app.get("/api/cv", (req, res) => {
  const userData = auth.requireAuth(req, res);
  if (!userData) return;
  const { sub, auth: role } = userData;

  db.get("SELECT * FROM cvs WHERE email=?", sub, (err, data) => {
    if (err) {
      return internalError(res, err);
    }
    if (data === undefined) {
      return userError(res, "No CV for this user");
    }
    // We need a way to pass this info to the download endpoint securely.
    const metadata = { sub, target: data["storage"], auth: data["filename"] };
    const token = auth.generateToken(metadata);

    return res.json({
      status: "success",
      token: token
    });
  });
});

app.put("/api/cv", upload.single("cv"), (req, res) => {
  const userData = auth.requireAuth(req, res);
  if (!userData) return;
  const { sub } = userData;

  if (!req.file.path)
    return userError(res, "No file uploaded");

  db.run("INSERT OR REPLACE INTO cvs (email, filename, storage_path) VALUES (?, ?, ?)",
         [sub, req.file.originalname, req.file.filename],
         err => {
    if (err) {
      return internalError(res, err);
    }
    res.json({status: "success"});
  });
});

// GENERIC ENDPOINTS
//  - GET /api/download: Download files
//  - GET /api/flag:     Internal management endpoint (admin gets a flag here)
//  - GET /*: Main page
app.get('/api/download', (req, res) => {
  const downloadToken = auth.extractBearer(req);
  if (!downloadToken.valid)
    return res.status(403).json({error: downloadToken.error});
  const result = auth.validateToken(downloadToken.token);
  if (!result.valid)
    return res.status(403).json({error: result.error});
  const { target, filename } = result.payload;
  const targetPath = path.join(UPLOAD_DIR, target);
  if (!path.exists(targetPath))
    return res.status(404).json({error: "No such file (uploads are only kept for 60 minutes!)"});
  return res.attachment(filename).sendFile(targetPath);
});

app.get('/api/flag', (req, res) => {
  if (!auth.requireAuth(req, res, auth.ADMIN_ROLE))
    return;
  res.send(flags.getAdminFlag());
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(port, () => { console.log(`Broken Tutor Tool ready at http://127.0.0.1:${port}`); });
