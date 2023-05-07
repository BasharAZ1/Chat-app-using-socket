# Import required modules
import socket
import threading
from databases import queries as q

HOST = '127.0.0.1'
PORT = 1234  # You can use any port between 0 and 65535
LISTENER_LIMIT = 5
active_clients = []  # List of all currently connected users
active_clients_str = ''


# Function to listen for upcoming messages from a client
def listen_for_messages(client, username):
    while 1:

        message = client.recv(2048).decode()
        msg_parts = message.split(",")
        if len(msg_parts) == 2:
            if msg_parts[0] == 'log_out':
                active_clients.remove((msg_parts[1], client))
                q.change_status_login(msg_parts[1])
                global active_clients_str
                active_clients_str = active_clients_str.replace(msg_parts[1] + '###', '')
                send_messages_to_all('log_out,' + msg_parts[1] + ' Has left the chat,' + active_clients_str)
                client_handler(client)
                break
        if message != '':

            final_msg = username + ' ~ ' + message
            send_messages_to_all('message,' + final_msg)
            print(final_msg)

        else:
            print(f"The message send from client {username} is empty")


# Function to send message to a single client
def send_message_to_client(client, message):
    client.sendall(message.encode())


# Function to send any new message to all the clients that
# are currently connected to this server
def send_messages_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)


# Function to handle client
def client_handler(client):
    # Server will listen for client message that will
    # Contain the username

    while 1:

        message = client.recv(2048).decode()
        print(f"client handler message: {message}")

        # Split the message into parts using the delimiter ','
        msg_parts = message.split(',')

        if msg_parts[0] == "Sign Up":
            check_msg = q.add_user(msg_parts[1], msg_parts[2], msg_parts[3], msg_parts[4], msg_parts[5], msg_parts[6])
            client.sendall(check_msg.encode())

        elif msg_parts[0] == 'Sign in':
            check_msg = q.login(msg_parts[1], msg_parts[2])
            client.sendall(check_msg.encode())

        elif msg_parts[0] == 'userloggedin':
            active_clients.append((msg_parts[1], client))
            global active_clients_str
            active_clients_str = active_clients_str + msg_parts[1] + '###'
            print(active_clients_str)
            send_messages_to_all('userloggedin,' + msg_parts[1] + ' Has joined the chat,' + active_clients_str)
            break

        elif msg_parts[0] == 'log_out':
            q.change_status_login(msg_parts[1])
            active_clients.remove((msg_parts[1], client))
            active_clients_str = active_clients_str.replace(msg_parts[1] + '###', '')
            send_messages_to_all('log_out,' + msg_parts[1] + ' Has left the chat,' + active_clients_str)

    threading.Thread(target=listen_for_messages, args=(client, msg_parts[1],)).start()


# Main function

def main():
    # Creating the socket class object
    # AF_INET: we are going to use IPv4 addresses
    # SOCK_STREAM: we are using TCP packets for communication
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    q.create_users_table()
    # q.add_user("ayal123","Aa123456","ayal","abo", "male", "ayal123@gmail.com")
    # q.add_user("kinan123", "Aa123456", "kinan", "hino", "male", "kinan@gmail.com")
    # q.add_user("BasharAli159", "Aa123456", "bash", "ali", "female", "basha@gmail.com")
    # print(q.change_status_login("ayal123"))
    # Creating a try catch block
    try:
        # Provide the server with an address in the form of
        # host IP and port
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")

    except socket.error:
        print(f"Unable to bind to host {HOST} and port {PORT}")

    # Set server limit
    server.listen(LISTENER_LIMIT)
    while 1:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")
        # active_clients.add(client)
        threading.Thread(target=client_handler, args=(client,)).start()


if __name__ == '__main__':
    main()
