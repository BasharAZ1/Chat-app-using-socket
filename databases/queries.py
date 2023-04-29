import mysql.connector
import re
import hashlib
import mysql.connector

HOST = "localhost"
USER = "root"
PASSWORD = "12332100"
DATABASE = "chatdb"

def create_connection():
    try:
        connection = mysql.connector.connect(
            host=HOST,
            user=USER,
            password=PASSWORD,
            database=DATABASE
        )
        return connection
    except mysql.connector.Error as error:
        print("Error connecting to MySQL database: {}".format(error))

# def create_users_table():
#     connection = create_connection()
#     cursor = connection.cursor()
#     cursor.execute("""CREATE TABLE IF NOT EXISTS users (
#                         email VARCHAR(255) PRIMARY KEY,
#                         username VARCHAR(255) UNIQUE,
#                         password VARCHAR(255),
#                         birthdate DATE
#                      )""")
#     connection.commit()
#     connection.close()


def create_users_table():
    connection = create_connection()

    if connection is None:
        print("Error connecting to MySQL database")
        return

    cursor = connection.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS usertable (
                        
                        username VARCHAR(255) UNIQUE,
                        password VARCHAR(255),
                        firstname VARCHAR(255),
                        lastname VARCHAR(255),
                        gender VARCHAR(255),
                        email VARCHAR(255) PRIMARY KEY
                     )""")

    connection.commit()
    connection.close()

def hash_password(password):
    # Convert the password to bytes
    password_bytes = password.encode('utf-8')
    # Hash the password using SHA-256
    hashed_bytes = hashlib.sha256(password_bytes).digest()
    # Convert the hashed bytes to a string
    hashed_password = hashed_bytes.hex()
    return hashed_password

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password) or not re.search("[a-z]", password):
        return False
    return True

# def add_user(email, username, password, birthdate):
#     if not is_valid_password(password):
#         print("Invalid password. at least 8 long and 1 capital 1 small")
#         return False
#
#     connection = create_connection()
#     cursor = connection.cursor()
#
#     try:
#         cursor.execute("INSERT INTO users (email, username, password, birthdate) VALUES (%s, %s, %s, %s)",
#                        (email, username, password, birthdate))
#         connection.commit()
#         print("User added successfully.")
#         return True
#     except mysql.connector.errors.IntegrityError:
#         print("User with this email or username already exists.")
#         return False
#     finally:
#         connection.close()


def add_user(username, password, first_name, last_name, gender, email):
    if not is_valid_password(password):
        print("Invalid password.")
        print("length 8 atleast,and one small and big characters")
        return False

    hashed_pass = hash_password(password)

    connection = create_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("INSERT INTO chatdb.usertable (username, password, firstname, lastname, gender, email)"
                       " VALUES (%s, %s, %s, %s, %s, %s)",
                       (username, hashed_pass, first_name, last_name, gender, email))

        connection.commit()
        print("User added successfully.")
        return True
    except mysql.connector.errors.IntegrityError:
        print("User with this email or username already exists.")
        return False
    finally:
        connection.close()


def login(username, password):
    connection = create_connection()
    cursor = connection.cursor()
    query = "SELECT password FROM chatdb.usertable WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    if result is None:

        return False
    hashed_pass = result[0]
    hash_input = hash_password(password)
    if hash_input == hashed_pass:
        print("Login successful.")
        return True
    else:
        print("Invalid password.")
        return False
