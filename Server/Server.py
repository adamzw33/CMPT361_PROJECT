import socket
import os
import json
import glob
import datetime
import sys


DB_PATH = "user_pass.json" #setting the json database for later calls

try:
    with open(DB_PATH, "r", encoding="utf-8") as f:
        database = json.load(f)
        if not isinstance(database, dict):
            database = {}
except (FileNotFoundError, json.JSONDecodeError):
    database = {}

def server():
    serverPort = 13000

    # Create the server socket (IPv4, TCP)
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('', serverPort))
        serverSocket.listen(1)
    except Exception as e:
        print("Server socket error:", e)
        sys.exit(1)

    while True:
        try:
            connectionSocket, addr = serverSocket.accept()

            # Welcome and username prompt
            connectionSocket.send("Enter your username: ".encode('ascii'))
            data = connectionSocket.recv(2048)
            if not data:
                connectionSocket.close()
                continue
            username = data.decode('ascii').strip()

            # Validate username
            
            if username not in database.json:
                connectionSocket.send("Incorrect username. Connection terminated.\n".encode('ascii'))
                connectionSocket.close()
                continue

            # pormpt password
            connectionSocket.send("Enter your password: ".encode('ascii'))
            data = connectionSocket.recv(2048)
            if not data:
                connectionSocket.close()
                continue
            password = data.decode('ascii').strip()

            # Validate password
            

            # Main menu loop
            while True:
                menu = ("Select the operation:\n"
                            "1) Create and send an email\n"
                            "2) Display the inbox list\n"
                            "3) Display the email contents\n"
                            "4) Terminate the connection\n"
                            "Choice: ")
                connectionSocket.send(menu.encode('ascii'))

                # Receive choice
                data = connectionSocket.recv(2048)
                if not data:
                    break
                choice = data.decode('ascii').strip()

                # Option 1: Create and send an email
                if choice == '1':
