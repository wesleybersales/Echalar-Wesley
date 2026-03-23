import os
from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import re
from config import Config

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY


# DATABASE CONNECTION
def get_db():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# DATABASE INITIALIZATION
def init_db():
    conn = sqlite3.connect(Config.DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


# INPUT VALIDATION
def valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


# HOME PAGE
@app.route("/")
def index():
    return render_template("index.html")


# REGISTER PAGE
@app.route("/register", methods=["GET", "POST"])
def register():
    try:
        if request.method == "POST":

            email = request.form["email"].strip()
            password = request.form["password"]

            # Input validation
            if not valid_email(email):
                return "Invalid email format"

            if len(password) < 6:
                return "Password must be at least 6 characters"

            # Hash password
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            conn = get_db()
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, hashed_password)
            )

            conn.commit()
            conn.close()

            return redirect("/login")

        return render_template("register.html")

    except sqlite3.IntegrityError:
        return "User already exists"

    except Exception:
        return "Registration error occurred"


# LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":

            email = request.form["email"].strip()
            password = request.form["password"]

            conn = get_db()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            )

            user = cursor.fetchone()
            conn.close()

            if user and bcrypt.checkpw(password.encode(), user["password"]):
                session["user_id"] = user["id"]
                return redirect("/dashboard")

            return "Invalid email or password"

        return render_template("login.html")

    except Exception:
        return "Login error"


# DASHBOARD (Protected Page)
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    return render_template("dashboard.html")


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# RUN APPLICATION
if __name__ == "__main__":
    init_db()  # Automatically creates database and table
    app.run(debug=True)