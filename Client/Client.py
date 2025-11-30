import socket
import sys
import os, glob, datetime
import json


def client():
    serverName = 'localhost'
    serverPort = 13000
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as err:
        print(f"Socket creation error: {e}")
        sys.exit(1)