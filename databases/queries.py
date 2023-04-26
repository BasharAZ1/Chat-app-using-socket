import mysql.connector
import re

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

    cursor.execute("""CREATE TABLE IF NOT EXISTS test (
                        email VARCHAR(255) PRIMARY KEY,
                        username VARCHAR(255) UNIQUE,
                        password VARCHAR(255),
                        birthdate DATE
                     )""")

    connection.commit()
    connection.close()


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


def add_user(email, username, password, birthdate):
    if not is_valid_password(password):
        print("Invalid password.")
        print("length 8 atleast,and one small and big characters")
        return False

    connection = create_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("INSERT INTO chatdb.users (email, username, password, birthdate) VALUES (%s, %s, %s, %s)",
                       (email, username, password, birthdate))

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

    cursor.execute("SELECT password FROM chatdb.users WHERE username = %s", (username,))
    result = cursor.fetchone()

    if result and result[0] == password:
        print("Login successful.")
        return True
    else:
        print("Invalid username or password.")
        return False
