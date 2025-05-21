from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'your_secret_key'
CORS(app)

def get_db_connection():
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        print("Database connection successful")
        return conn
    except sqlite3.Error as e:
        print("Database connection error:", e)
        return None

# Web routes
@app.route('/')
def home():
    if 'username' in session:
        conn = get_db_connection()
        posts = conn.execute('SELECT * FROM posts').fetchall()
        conn.close()
        return render_template('home.html', username=session['username'], posts=posts)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Username atau password salah!')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_pw = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return 'Username sudah ada!'

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        conn = get_db_connection()
        conn.execute('INSERT INTO posts (author, title, content) VALUES (?, ?, ?)', (session['username'], title, content))
        conn.commit()
        conn.close()
        return redirect(url_for('home'))

    return render_template('create.html')

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if post is None or post['author'] != session['username']:
        return 'Post tidak ditemukan atau tidak diizinkan.', 403

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn.execute('UPDATE posts SET title = ?, content = ? WHERE id = ?', (title, content, post_id))
        conn.commit()
        conn.close()
        return redirect(url_for('home'))

    conn.close()
    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if post is None or post['author'] != session['username']:
        return 'Post tidak ditemukan atau tidak diizinkan.', 403

    conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('home'))

@app.route('/edit_account', methods=['GET', 'POST'])
def edit_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']

        conn = get_db_connection()

        if new_username:
            conn.execute('UPDATE users SET username = ? WHERE username = ?', (new_username, current_user))
            session['username'] = new_username

        if new_password:
            hashed_pw = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_pw, session['username']))

        conn.commit()
        conn.close()
        return redirect(url_for('home'))

    return render_template('edit_account.html', username=current_user)

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = session['username']

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE username = ?', (user,))
    conn.execute('DELETE FROM posts WHERE author = ?', (user,))
    conn.commit()
    conn.close()

    session.pop('username', None)
    return redirect(url_for('register'))

# API routes (from insomnia.py)
@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/api/', methods=['GET', 'POST'])
def api_home():
    if request.method == 'POST':
        return jsonify({'status': 'success', 'message': 'Data diterima via POST'})
    
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

@app.route('/api/login', methods=['POST'])
def api_login():
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

@app.route('/api/register', methods=['POST'])
def api_register():
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

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('username', None)
    return jsonify({'status': 'success', 'message': 'Logged out successfully'})

@app.route('/api/create', methods=['POST'])
def api_create():
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
        


@app.route('/api/edit_post/<int:post_id>', methods=['PUT'])
def api_edit_post(post_id):
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

@app.route('/api/delete_post/<int:post_id>', methods=['DELETE'])
def api_delete_post(post_id):
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

@app.route('/api/post/<int:post_id>', methods=['GET'])
def get_post_by_id(post_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500

    try:
        post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
        if post is None:
            return jsonify({'status': 'error', 'message': 'Resource not found'}), 404

        return jsonify({
            'status': 'success',
            'post': {
                'id': post['id'],
                'title': post['title'],
                'content': post['content'],
                'author': post['author']
            }
        })
    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'status': 'error', 'message': 'Database operation failed'}), 500
    finally:
        conn.close()

@app.route('/api/delete_account', methods=['DELETE'])
def api_delete_account():
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