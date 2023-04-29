# import required modules
import socket
import threading
import tkinter as tk
import re
from tkinter import scrolledtext, BOTH, ttk
from tkinter import messagebox
import customtkinter
import tkinter.messagebox as messagebox

HOST = '127.0.0.1'
PORT = 1234
Error_message_flag = False
FONT_labels = ("Helvetica", 30)
DARK_GREY = '#121212'
DARK_GREY_Sign_UP = '#A9A9A9'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Helvetica", 14)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)

# Creating a socket object
# AF_INET: we are going to use IPv4 addresses
# SOCK_STREAM: we are using TCP packets for communication
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

import tkinter.messagebox as messagebox


def register_user(Sign_up_page, window, Username, password1, password2, FirstName, LastName, gender, Email):
    if not Username:
        messagebox.showerror("Error", "Please enter a username")
        window.focus()
        return
    elif not is_valid_password(password1) or not is_valid_password(password2):
        messagebox.showerror("Error", " At least 8 characters\n At least one capital and one small character \n both "
                                      "password must match")
        window.focus()
        return
    elif password1 != password2:
        messagebox.showerror("Error", "Passwords do not match")
        window.focus()
        return

    elif not FirstName:
        messagebox.showerror("Error", "Please enter a FirstName")
        window.focus()
        return
    elif not LastName:
        messagebox.showerror("Error", "Please enter a LastName")
        window.focus()
        return
    elif gender == 'Select':
        messagebox.showerror("Error", "Please Select Gender")
        window.focus()
        return

    elif not is_valid_email(Email):
        messagebox.showerror("Error", "Please Enter Valid Email ")
        window.focus()
        return
    else:
        register_message = 'Sign Up,' + Username + ',' + password1 + ',' + FirstName + ',' + LastName + ',' + gender + ',' + Email
        # try except block
        try:
            # Connect to the server
            client.connect((HOST, PORT))
            print("Successfully connected to server")
            client.sendall(register_message.encode())
            print("Register message sent successfully")
            messagebox.showinfo("Success", "User registered successfully!")
        except ConnectionRefusedError:
            messagebox.showerror("Unable to connect to server", f"Unable to connect to server {HOST} {PORT}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")


def Connect_user(Username, password):
    print(Username + password)


def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password) or not re.search("[a-z]", password):
        return False
    return True


def on_label_click():
    print("Label clicked")
    Sign_up_page = tk.Toplevel()
    Sign_up_page.title("Sign up")
    Sign_up_page.geometry("600x600")
    Sign_up_page.focus()
    # Username field
    window = tk.Frame(Sign_up_page, width=600, height=600, bg=DARK_GREY_Sign_UP)
    window.pack(expand=1, fill=BOTH)
    username_label = tk.Label(window, text="Username", font=FONT, bg=DARK_GREY_Sign_UP, fg=WHITE)
    username_label.grid(row=0, column=0, padx=0, pady=10, sticky="w")
    username_entry = customtkinter.CTkEntry(window, width=200, font=('Arial', 16), height=3, corner_radius=8)
    username_entry.grid(row=0, column=1, padx=0, pady=10)

    # Password fields
    password_label = tk.Label(window, text="Password", font=FONT, bg=DARK_GREY_Sign_UP, fg=WHITE)
    password_label.grid(row=1, column=0, padx=0, pady=10, sticky="w")
    password_entry = customtkinter.CTkEntry(window, show="*", width=200, font=('Arial', 16), height=3, corner_radius=8)
    password_entry.grid(row=1, column=1, padx=0, pady=10)

    password_label2 = tk.Label(window, text="Confirm Password", font=FONT, bg=DARK_GREY_Sign_UP, fg=WHITE)
    password_label2.grid(row=2, column=0, padx=0, pady=10, sticky="w")
    password_entry2 = customtkinter.CTkEntry(window, show="*", width=200, font=('Arial', 16), height=3, corner_radius=8)
    password_entry2.grid(row=2, column=1, padx=0, pady=10)

    # First name field
    first_name_label = tk.Label(window, text="First Name", font=FONT, bg=DARK_GREY_Sign_UP, fg=WHITE)
    first_name_label.grid(row=3, column=0, padx=0, pady=10, sticky="w")
    first_name_entry = customtkinter.CTkEntry(window, width=200, font=('Arial', 16), height=3, corner_radius=8)
    first_name_entry.grid(row=3, column=1, padx=0, pady=10)

    # Second name field
    second_name_label = tk.Label(window, text="Last Name", font=FONT, bg=DARK_GREY_Sign_UP, fg=WHITE)
    second_name_label.grid(row=4, column=0, padx=0, pady=10, sticky="w")
    second_name_entry = customtkinter.CTkEntry(window, width=200, font=('Arial', 16), height=3, corner_radius=8)
    second_name_entry.grid(row=4, column=1, padx=0, pady=10)

    # Gender field
    gender_label = tk.Label(window, text="Gender", font=FONT, bg=DARK_GREY_Sign_UP, fg=WHITE)
    gender_label.grid(row=5, column=0, padx=0, pady=10, sticky="w")

    gender_var = tk.StringVar(value="Select")
    gender_combobox = customtkinter.CTkComboBox(master=window,
                                                values=["Select", "Male", "Female"], width=200)
    gender_combobox.grid(row=5, column=1, padx=10, pady=10, sticky="w")
    gender_combobox.set("Select")

    # Email field
    email_label = tk.Label(window, text="Email", font=FONT, bg=DARK_GREY_Sign_UP, fg=WHITE)
    email_label.grid(row=6, column=0, padx=0, pady=10, sticky="w")
    email_entry = customtkinter.CTkEntry(window, width=200, font=('Arial', 16), height=3, corner_radius=8)
    email_entry.grid(row=6, column=1, padx=0, pady=10)

    # Submit button
    submit_button = customtkinter.CTkButton(window, text="Submit", corner_radius=8, height=10, width=200,
                                            font=('Arial', 24),
                                            command=lambda: register_user(Sign_up_page, window, username_entry.get(),
                                                                          password_entry.get(), password_entry2.get(),
                                                                          first_name_entry.get(),
                                                                          second_name_entry.get(),
                                                                          gender_combobox.get(), email_entry.get()))
    submit_button.grid(row=7, column=2, padx=0, pady=40, sticky="e")


def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)


def connect():
    # try except block
    try:

        # Connect to the server
        client.connect((HOST, PORT))
        print("Successfully connected to server")
        add_message("[SERVER] Successfully connected to the server")
    except:
        messagebox.showerror("Unable to connect to server", f"Unable to connect to server {HOST} {PORT}")

    username = username_textbox.get()
    if username != '':
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")

    threading.Thread(target=listen_for_messages_from_server, args=(client,)).start()

    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)


def send_message():
    message = message_textbox.get()
    if message != '':
        client.sendall(message.encode())
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")


LoginPage = tk.Tk()
LoginPage.geometry("600x600")
LoginPage.title("Login")
LoginPage.resizable(False, False)

LoginPage_topFrame = tk.Frame(LoginPage, width=600, height=600, bg=DARK_GREY)
LoginPage_topFrame.pack(expand=1, fill=BOTH)

Login_label = tk.Label(LoginPage_topFrame, text="Sign in", font=FONT_labels, bg=DARK_GREY, fg=WHITE)
Login_label.grid(row=0, column=1, padx=20, pady=20, columnspan=1, sticky="nsew")

Username_label = tk.Label(LoginPage_topFrame, text="Username", font=FONT, bg=DARK_GREY, fg=WHITE, justify="left")
Username_label.grid(row=4, column=0, padx=30, pady=10, sticky="nsew")
Username_textbox = customtkinter.CTkEntry(master=LoginPage_topFrame, height=3, width=200, corner_radius=8)
Username_textbox.grid(row=4, column=1, padx=0, pady=10, sticky="nsew")
password_label = tk.Label(LoginPage_topFrame, text="Password", font=FONT, bg=DARK_GREY, fg=WHITE)
password_label.grid(row=5, column=0, padx=30, pady=10, sticky="nsew")
Password_textbox = customtkinter.CTkEntry(master=LoginPage_topFrame, height=3, width=200, corner_radius=8, show="*")
Password_textbox.grid(row=5, column=1, padx=0, pady=10, sticky="nsew")

Login_button = customtkinter.CTkButton(LoginPage_topFrame, text="Login", text_color='white', corner_radius=8,
                                       height=30,
                                       width=150, bg_color=OCEAN_BLUE,
                                       command=lambda: Connect_user(Username_textbox.get(), Password_textbox.get()))
Login_button.grid(row=6, column=1, padx=20, pady=20, sticky="nsew")
Forget_password_label = customtkinter.CTkLabel(LoginPage_topFrame, text="Forgot Password?", height=10, width=10,
                                               anchor='center',
                                               font=('Arial', 16), bg_color=DARK_GREY, text_color='#D3D3D3')

Forget_password_label.grid(row=7, column=1, padx=5, pady=0, sticky="ne")
Sign_Up_label = customtkinter.CTkLabel(LoginPage_topFrame, text="Need an account? Sign up", height=10, width=10,
                                       anchor='center',
                                       font=('Arial', 20), bg_color=DARK_GREY, text_color='#0077cc')
Sign_Up_label.grid(row=8, column=1, padx=5, pady=280, sticky="nsew")
Sign_Up_label.bind("<Button-1>", lambda event: on_label_click())


# root = tk.Toplevel()
# root.geometry("600x600")
# root.title("Client Messenger")
# root.resizable(False, False)
#
# root.grid_rowconfigure(0, weight=1)
# root.grid_rowconfigure(1, weight=4)
# root.grid_rowconfigure(2, weight=1)
#
# top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
# top_frame.grid(row=0, column=0, sticky=tk.NSEW)
#
# middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
# middle_frame.grid(row=1, column=0, sticky=tk.NSEW)
#
# bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
# bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)
#
# username_label = tk.Label(top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE)
# username_label.pack(side=tk.LEFT, padx=10)
#
# username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
# username_textbox.pack(side=tk.LEFT)
#
# username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
# username_button.pack(side=tk.LEFT, padx=15)
#
# message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=38)
# message_textbox.pack(side=tk.LEFT, padx=10)
#
# message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
# message_button.pack(side=tk.LEFT, padx=10)
#
# message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=67, height=26.5)
# message_box.config(state=tk.DISABLED)
# message_box.pack(side=tk.TOP)


def listen_for_messages_from_server(client):
    while 1:

        message = client.recv(2048).decode('utf-8')
        if message != '':
            username = message.split("~")[0]
            content = message.split('~')[1]

            add_message(f"[{username}] {content}")

        else:
            messagebox.showerror("Error", "Message received from client is empty")


# main function
def main():
    LoginPage.mainloop()


if __name__ == '__main__':
    main()
