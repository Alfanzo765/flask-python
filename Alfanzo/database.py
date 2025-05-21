import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

def add_post(author, title, content):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO posts (author, title, content) VALUES (?, ?, ?)', (author, title, content))
    conn.commit()
    conn.close()

init_db()
