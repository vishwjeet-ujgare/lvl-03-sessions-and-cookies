// Import required modules
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10; // Number of salt rounds for hashing passwords
env.config(); // Load environment variables

// 🏨 Step 1: Set Up Express-Session (Hotel Reception Setup)
// - The session will store authentication data on the server.
// - The session ID is sent to the client as a cookie.
app.use(
  session({
    secret: "TOPSECRETWORD", // Used to sign/encrypt the session ID in the cookie (prevents tampering)
    resave: false, // Prevents resaving unchanged sessions (improves performance)
    saveUninitialized: true, // Creates a session for every visitor, even if they haven't logged in
  })
);

// Middleware for parsing form data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); // Serves static files (CSS, images, etc.)

// 🏨 Step 2: Initialize Passport (Security System Setup)
// - Initializes authentication handling
// - Connects authentication to session storage
app.use(passport.initialize());
app.use(passport.session()); // Enables persistent login using sessions

// 🏨 Step 3: Connect to PostgreSQL Database (Hotel Guest Database)
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "123456",
  port: 5432,
});
db.connect(); // Establish database connection

// Route for home page
app.get("/", (req, res) => {
  res.render("home.ejs");
});

// Route for login page
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

// Route for register page
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// 🏨 Step 4: Logout (Guest Checks Out, Key Card is Revoked)
// - `req.logout()` removes session data, so the user is logged out
// - The session cookie is invalidated
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// 🏨 Step 5: Protecting the Secrets Page (Restricted Area Requires a Valid Key Card)
// - Only authenticated users can access this page
// - `req.isAuthenticated()` checks if the session ID is valid
app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login"); // Redirects guests without valid session IDs
  }
});

// 🏨 Step 6: User Login (Guest Checks In, Session is Created)
// - Uses `passport.authenticate()` to check credentials
// - If successful, user is redirected to `/secrets`
// - If failed, user is redirected back to `/login`
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// 🏨 Step 7: User Registration (New Guest Registers at Reception)
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // Check if the email is already registered
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login"); // Redirect existing users to login
    } else {
      // Hash the password for security
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          // Store the new user in the database
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];

          // Auto-login the user after registration
          req.login(user, (err) => {
            console.log("Registration successful");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// 🏨 Step 8: Local Strategy Authentication (Checking Guest Identity)
// - `passport.use(new Strategy(...))` defines the login process
// - The verify function checks if the provided credentials match the database
passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      // Check if the user exists in the database
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;

        // Compare hashed password with entered password
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user); // Login successful
            } else {
              return cb(null, false); // Incorrect password
            }
          }
        });
      } else {
        return cb("User not found"); // User doesn't exist
      }
    } catch (err) {
      console.log(err);
    }
  })
);

// 🏨 Step 9: Storing & Retrieving Session Data (Hotel Record System)
// - `serializeUser()` stores only the user ID in the session (to keep it lightweight)
// - `deserializeUser()` retrieves the full user object from the database when needed
passport.serializeUser((user, cb) => {
  cb(null, user.id); // Store only user ID in session
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]); // Retrieve full user details from database
  } catch (err) {
    cb(err);
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
