from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Config
app.config['JWT_SECRET_KEY'] = 'change-this-to-random-string'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # 10MB max

CORS(app)
jwt = JWTManager(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        name TEXT,
        profile_pic TEXT
    )''')
    conn.commit()
    conn.close()

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"msg": "Missing fields"}), 400

    conn = get_db()
    try:
        hashed = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, email, password) VALUES (?,?,?)",
                     (username, email, hashed))
        conn.commit()
        return jsonify({"msg": "User created"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"msg": "Username or email already exists"}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username =?", (username,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        print("User ID type:", type(user['id']), "Value:", user['id'])
        token = create_access_token(identity=str(user['id']))
        return jsonify({"access_token": token}), 200
    return jsonify({"msg": "Bad credentials"}), 401

@app.route('/api/profile', methods=['PUT', 'OPTIONS'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    name = request.json.get('name')
    
    # Hardcoded but unique per user - no uploads needed
    profile_pic = f"https://i.pravatar.cc/300?u={current_user_id}"
    
    conn = get_db()
    if name:
        conn.execute("UPDATE users SET name=?, profile_pic=? WHERE id=?", (name, profile_pic, current_user_id))
    else:
        conn.execute("UPDATE users SET profile_pic=? WHERE id=?", (profile_pic, current_user_id))
    conn.commit()
    conn.close()
    
    return jsonify({"msg": "Profile updated", "profile_pic": profile_pic}), 200


# NEW: Get profile data
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    conn = get_db()
    user = conn.execute("SELECT id, name, email, profile_pic FROM users WHERE id =?", (current_user_id,)).fetchone()
    conn.close()

    if user:
        pic_url = user['profile_pic'] if user['profile_pic'] else None
        return jsonify({"id": user['id'], "name": user['name'], "email": user['email'], "profile_pic": pic_url})
    return jsonify({"msg": "User not found"}), 404

# START SERVER
if __name__ == '__main__':
    init_db()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
