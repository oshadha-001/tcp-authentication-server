
import socket

HOST="127.0.0.1"
PORT=50920

def send(sock,msg):
    data=f"LEN:{len(msg)}\n{msg}"
    sock.send(data.encode())
    print(sock.recv(4096).decode())

s=socket.socket()
s.connect((HOST,PORT))

while True:
    cmd=input(">> ")
    send(s,cmd)
