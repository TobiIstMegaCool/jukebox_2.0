import os
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, redirect, request, render_template, session
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_session import Session
import psycopg2
import psycopg2.extras
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import html

# -----------------------------
# APP SETUP
# -----------------------------
app = Flask(__name__, template_folder='../frontend')
CORS(app,
    resources={
        r"/api/*": {
            "origins": ["*"],
            "methods": ["GET", "POST", "PATCH", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    }
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# -----------------------------
# Rate Limiter
# -----------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


# -----------------------------
# Sanitization
# -----------------------------
def sanitize_string(value, max_length=255):
    if not isinstance(value, str):
        return ""
    sanitized = html.escape(value.strip())
    return sanitized[:max_length]

def sanitize_int(value, min_val=None, max_val=None):
    try:
        val = int(value)
        if min_val is not None and val < min_val:
            return min_val
        if max_val is not None and val > max_val:
            return max_val
        return val
    except (ValueError, TypeError):
        return None


# -----------------------------
# SECURITY SETTINGS
# -----------------------------
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-prod")

app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

Session(app)
bcrypt = Bcrypt(app)

# -----------------------------
# DATABASE CONFIG (POSTGRES)
# -----------------------------
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("POSTGRES_DB", "jukebox")
DB_USER = os.environ.get("POSTGRES_USER", "jukebox")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "jukebox")
DB_PORT = os.environ.get("DB_PORT", "5432")


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    # Users table with cleaned column
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    # Reviews table
    c.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id SERIAL PRIMARY KEY,
            userId TEXT NOT NULL,
            appId TEXT NOT NULL,
            title TEXT NOT NULL,
            reviewText TEXT NOT NULL,
            stars INTEGER NOT NULL,
            createdAt TIMESTAMP NOT NULL,
            updatedAt TIMESTAMP
        )
    """)

    # Default admin user
    c.execute("SELECT id FROM users LIMIT 1")
    if not c.fetchone():
        default_hash = bcrypt.generate_password_hash("admin123").decode("utf-8")
        c.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            ("admin", default_hash)
        )

    conn.commit()
    c.close()
    conn.close()


# Initialize DB at startup
init_db()


# -----------------------------
# AUTH DECORATOR
# -----------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# -----------------------------
# ROUTES
# -----------------------------
@app.route("/")
@limiter.limit("5 per minute")
def home():
    if "user" not in session:
        return redirect("/login")
    return render_template("index.html")


@app.route("/login")
@limiter.limit("5 per minute")
def login_page():
    return render_template("login.html")


@app.route("/signup")
@limiter.limit("5 per minute")
def signup_page():
    return render_template("signup.html")


# -----------------------------
# AUTH API
# -----------------------------
@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(force=True)
    
    username = sanitize_string(data.get("username"))
    password = sanitize_string(data.get("password"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not bcrypt.check_password_hash(user["password_hash"], password):
        return jsonify({"message": "Invalid credentials"}), 401

    session["user"] = username
    logger.info(f"User '{username}' logged in successfully.")
    return jsonify({"message": "Logged in"}), 200


@app.route("/api/signup", methods=["POST"])
@limiter.limit("3 per minute")
def signup():
    data = request.get_json(force=True)
    
    username = sanitize_string(data.get("username"))
    password = sanitize_string(data.get("password"))

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, pw_hash),
        )
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"User '{username}' registered successfully.")
        return jsonify({"message": "User created"}), 201
    except psycopg2.errors.UniqueViolation:
        return jsonify({"message": "User already exists"}), 409


@app.route("/logout")
def logout():
    username = session.get("user")
    session.clear()
    if username:
        logger.info(f"User '{username}' logged out.")
    return redirect("/login")


# -----------------------------
# REVIEWS API
# -----------------------------
@app.route('/api/reviews', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@login_required
def reviews_handler():
    conn = get_db_connection()
    c = conn.cursor()

    if request.method == 'GET':
        user_id = request.args.get('userId')
        app_id = request.args.get('appId')

        if not user_id or not app_id:
            return jsonify({"error": "Missing query parameters"}), 400

        c.execute(
            "SELECT * FROM reviews WHERE userId=%s AND appId=%s ORDER BY id DESC",
            (user_id, app_id)
        )
        reviews = []
        for row in c.fetchall():
            reviews.append({
                "id": row["id"],
                "userId": row["userid"],
                "appId": row["appid"],
                "title": row["title"],
                "reviewText": row["reviewtext"],
                "stars": row["stars"],
                "createdAt": row["createdat"],
                "updatedAt": row["updatedat"],
            })

        c.close()
        conn.close()
        return jsonify(reviews)

    elif request.method == 'POST':
        data = request.get_json(force=True)
        created_at = datetime.now().isoformat()

        user_id = sanitize_string(data['userId'])
        app_id = sanitize_string(data['appId'])
        title = sanitize_string(data['title'])
        review_text = sanitize_string(data['reviewText'])
        stars = sanitize_int(data['stars'])

        c.execute("""
            INSERT INTO reviews (userId, appId, title, reviewText, stars, createdAt)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            user_id,
            app_id,
            title,
            review_text,
            stars,
            created_at
        ))

        review_id = c.fetchone()
        conn.commit()
        c.close()
        conn.close()
        logger.info(f"Review created by user '{user_id}' for '{app_id}' with ID '{review_id}'")
        return jsonify({
            "id": review_id,
            "userId": data["userId"],
            "appId": data["appId"],
            "title": data["title"],
            "reviewText": data["reviewText"],
            "stars": data["stars"],
            "createdAt": created_at,
            "updatedAt": None
        }), 201


@app.route("/api/reviews/<int:review_id>", methods=["PATCH", "DELETE"])
@limiter.limit("10 per minute")
@login_required
def modify_review(review_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM reviews WHERE id=%s", (review_id,))
    review = cur.fetchone()
    
    if request.method == "DELETE":
        cur.execute("DELETE FROM reviews WHERE id=%s", (review_id,))
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Review {review_id} deleted by user.")
        return jsonify({"message": "Deleted"}), 200

    data = request.get_json(force=True)

    title = sanitize_string(data['title']) if 'title' in data else review['title']
    review_text = sanitize_string(data['reviewText']) if 'reviewText' in data else review['reviewText']
    stars = sanitize_int(data['stars']) if 'stars' in data else review['stars']

    cur.execute(
        """UPDATE reviews
           SET title=%s, reviewText=%s, stars=%s, updatedAt=%s
           WHERE id=%s
           RETURNING *""",
        (
            title,
            review_text,
            stars,
            datetime.utcnow(),
            review_id,
        ),
    )
    review = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    logger.info(f"Review {review_id} updated by user '{review['userId']}'.")
    return jsonify(review), 200


# -----------------------------
# ERROR HANDLING
# -----------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)