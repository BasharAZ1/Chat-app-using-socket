import hashlib
import re
import sqlite3

DATABASE = "databases/database.db"


def create_connection():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        # print(f'Successful connection to {DATABASE}')
    except sqlite3.Error as e:
        print(e)
    return conn


def create_users_table():
    conn = create_connection()

    if conn is None:
        print("Error connecting to SQLite database")
        return

    cur = conn.cursor()
    query = """CREATE TABLE IF NOT EXISTS user_table (
        username TEXT UNIQUE,
        password TEXT,
        firstname TEXT,
        lastname TEXT,
        gender TEXT,
        status INTEGER,
        email TEXT PRIMARY KEY
    )"""
    cur.execute(query)

    conn.commit()
    cur.close()
    conn.close()


def hash_password(password):
    password_bytes = password.encode('utf-8')
    hashed_bytes = hashlib.sha256(password_bytes).digest()
    hashed_password = hashed_bytes.hex()
    return hashed_password


def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password) or not re.search("[a-z]", password):
        return False
    return True


def add_user(username, password, first_name, last_name, gender, email):
    hashed_pass = hash_password(password)
    params = (username, hashed_pass, first_name, last_name, gender, 0, email)
    conn = create_connection()
    cur = conn.cursor()

    try:
        query = """INSERT INTO user_table (username, password, firstname, lastname, gender, status, email)
                VALUES (?, ?, ?, ?, ?, ?, ?)"""
        cur.execute(query, params)

        conn.commit()

        return "Sign Up, True, User added successfully."
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: user_table.username" in str(e):
            print("User with this username already exists.")
            return "Sign Up, False, User with this username already exists."
        elif "UNIQUE constraint failed: user_table.email" in str(e):
            print("User with this email already exists.")
            return "Sign Up, False, User with this email already exists."
        else:
            print("An error occurred while creating user.")
            return "Sign Up, False, An error occurred while creating user."
    finally:
        cur.close()
        conn.close()


def login(username, password):
    conn = create_connection()
    cur = conn.cursor()
    query = "SELECT password FROM user_table WHERE username = ?"
    cur.execute(query, (username,))
    result = cur.fetchone()

    if result is None:
        return "Sign in,False,invalid username"
    hashed_pass = result[0]
    hash_input = hash_password(password)
    if hash_input == hashed_pass:
        return "Sign in,True," + username
    else:

        return "Sign in,False,invalid password"


def create_messages_table():
    conn = create_connection()
    if conn is None:
        print("Error connecting to SQLite database")
        return
    cur = conn.cursor()
    query = """CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"""
    cur.execute(query)
    conn.commit()
    cur.close()
    conn.close()


def save_chat_messages(sender, message_text):
    conn = create_connection()
    if conn is None:
        print("Error connecting to SQLite database")
        return
    cur = conn.cursor()

    query = "INSERT INTO messages(sender,message) VALUES (?,?)"
    cur.execute(query, (sender, message_text))

    conn.commit()
    cur.close()
    conn.close()


def change_email_address(username, new_email):
    conn = create_connection()
    if conn is None:
        return False
    cur = conn.cursor()
    query = "UPDATE user_table SET email = ? WHERE username = ?"
    cur.execute(query, (new_email, username))

    conn.commit()
    cur.close()
    conn.close()
    return True

def change_status_login(username):

    conn = create_connection()
    if conn is None:
        return False
    cur = conn.cursor()
    status_query = 'SELECT status FROM user_table WHERE username = ?'
    cur.execute(status_query, (username,))
    user_status = cur.fetchone()[0]
    if user_status == 0:
        query = "UPDATE user_table SET status = 1 WHERE username = ?"
        cur.execute(query, (username,))
    else:
        query = "UPDATE user_table SET status = 0 WHERE username = ?"
        cur.execute(query, (username,))
    print(f"stattt {user_status}")
    conn.commit()
    cur.close()
    conn.close()
    return True

