from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
import sqlite3
import os

app = Flask(__name__)

# Set a secret key using an environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("Set the FLASK_SECRET_KEY environment variable first.")

bcrypt = Bcrypt(app)

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# Create the database
with get_db() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not 3 <= len(username) <= 30:
            message = "Username must be 3-30 characters."
        elif len(password) < 8 or len(password) > 72:
            message = "Password must be 8-72 characters."
        else:
            hashed_password = bcrypt.generate_password_hash(
                password
            ).decode("utf-8")

            try:
                with get_db() as db:
                    db.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (username, hashed_password)
                    )
                return redirect("/login")
            except sqlite3.IntegrityError:
                message = "Username already exists."

    return render_template("register.html", message=message)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and bcrypt.check_password_hash(
            user["password"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")

        message = "Invalid username or password."

    return render_template("login.html", message=message)

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=False)