import re
import hashlib
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

    cur.execute("""CREATE TABLE IF NOT EXISTS usertable (
        username TEXT UNIQUE,
        password TEXT,
        firstname TEXT,
        lastname TEXT,
        gender TEXT,
        email TEXT PRIMARY KEY
    )""")

    conn.commit()
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

    conn = create_connection()
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO usertable (username, password, firstname, lastname, gender, email)"
                       " VALUES (?, ?, ?, ?, ?, ?)",
                       (username, hashed_pass, first_name, last_name, gender, email))

        conn.commit()

        return "Sign Up, True, User added successfully."
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: usertable.username" in str(e):
            print("User with this username already exists.")
            return "Sign Up, False, User with this username already exists."
        elif "UNIQUE constraint failed: usertable.email" in str(e):
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
    query = "SELECT password FROM usertable WHERE username = ?"
    cur.execute(query, (username,))
    result = cur.fetchone()

    if result is None:
        return "Sign in,False,invalid username"
    hashed_pass = result[0]
    hash_input = hash_password(password)
    if hash_input == hashed_pass:
        return "Sign in,True,"+username
    else:

        return "Sign in,False,invalid password"
