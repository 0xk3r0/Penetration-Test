import socket

# Server's IP address and port
SRV_ADDR = '127.0.0.1'
SRV_PORT = 12345

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((SRV_ADDR, SRV_PORT))
print("Connected to the server.")

# Send data to the server
while True:
    message = input("Type your message (or type 'exit' to quit): ")
    if message.lower() == 'exit':
        break
    client_socket.sendall(message.encode())

    # Receive response from the server
    data = client_socket.recv(1024)
    print("Server:", data.decode())

# Close the connection
client_socket.close()
print("Connection closed.")
