'''
from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
CORS(app)

def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        print("Database connection successful")
        return conn
    except sqlite3.Error as e:
        print("Database connection error:", e)
        if conn:
            conn.close()
        return None

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        return "Data diterima via POST"
    
    if 'username' in session:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
            
        try:
            posts = conn.execute('SELECT * FROM posts').fetchall()
            posts_list = [dict(post) for post in posts]
            return jsonify({
                'status': 'success',
                'username': session['username'],
                'posts': posts_list
            })
        except sqlite3.Error as e:
            print("Database error:", e)
            return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
        finally:
            conn.close()
    return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate user
    ---
    tags:
      - auth
    parameters:
      - in: body
        name: credentials
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
      400:
        description: Invalid input
      401:
        description: Invalid credentials
    """
    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
    try:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return jsonify({
                'status': 'success',
                'message': 'Login successful',
                'username': username
            })
        else:
            return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
        
    if len(username) < 4 or len(username) > 20:
        return jsonify({'status': 'error', 'message': 'Username must be 4-20 characters'}), 400
        
    if len(password) < 8:
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters'}), 400

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
    try:
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
        conn.commit()
        return jsonify({
            'status': 'success',
            'message': 'Registration successful',
            'username': username
        })
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 409
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'status': 'success', 'message': 'Logged out successfully'})

@app.route('/create', methods=['POST'])
def create():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400
    
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({'status': 'error', 'message': 'Title and content required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO posts (author, title, content) VALUES (?, ?, ?)',
            (session['username'], title, content)
        )
        post_id = cursor.lastrowid
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Post created successfully',
            'post_id': post_id
        })
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

@app.route('/edit_post/<int:post_id>', methods=['PUT'])
def edit_post(post_id):
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400
    
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({'status': 'error', 'message': 'Title and content required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
    try:
        post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

        if post is None or post['author'] != session['username']:
            return jsonify({
                'status': 'error',
                'message': 'Post not found or not authorized'
            }), 403

        conn.execute(
            'UPDATE posts SET title = ?, content = ? WHERE id = ?',
            (title, content, post_id)
        )
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Post updated successfully',
            'post_id': post_id
        })
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

@app.route('/delete_post/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
    try:
        post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

        if post is None or post['author'] != session['username']:
            return jsonify({
                'status': 'error',
                'message': 'Post not found or not authorized'
            }), 403

        conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Post deleted successfully',
            'post_id': post_id
        })
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

@app.route('/edit_account', methods=['PUT'])
def edit_account():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400
    
    data = request.get_json()
    new_username = data.get('new_username')
    new_password = data.get('new_password')

    if not new_username and not new_password:
        return jsonify({
            'status': 'error',
            'message': 'Either new username or new password required'
        }), 400

    current_user = session['username']
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
    try:
        if new_username:
            if len(new_username) < 4 or len(new_username) > 20:
                return jsonify({'status': 'error', 'message': 'Username must be 4-20 characters'}), 400
                
            conn.execute(
                'UPDATE users SET username = ? WHERE username = ?',
                (new_username, current_user)
            )
            session['username'] = new_username

        if new_password:
            if len(new_password) < 8:
                return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters'}), 400
                
            hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
            conn.execute(
                'UPDATE users SET password = ? WHERE username = ?',
                (hashed_pw, session['username'])
            )

        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Account updated successfully',
            'username': session['username']
        })
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

@app.route('/delete_account', methods=['DELETE'])
def delete_account():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    user = session['username']

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
    try:
        conn.execute('DELETE FROM users WHERE username = ?', (user,))
        conn.execute('DELETE FROM posts WHERE author = ?', (user,))
        conn.commit()
        session.pop('username', None)
        
        return jsonify({
            'status': 'success',
            'message': 'Account deleted successfully',
            'username': user
        })
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
'''