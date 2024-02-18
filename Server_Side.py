import socket

# Server configuration
SRV_ADDR = '127.0.0.1'
SRV_PORT = 12345

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((SRV_ADDR, SRV_PORT))

# Listen for incoming connections
server_socket.listen(1)
print(f"Server started, listening on {SRV_ADDR}:{SRV_PORT}")

# Accept a connection
client_socket, client_address = server_socket.accept()
print(f"Client connected from {client_address}")

# Receive data from the client and echo it back
while True:
    data = client_socket.recv(1024)
    if not data:
        break
    print(f"Received data from client: {data.decode()}")  # Print received data
    client_socket.sendall(data)

# Close the connection
client_socket.close()
server_socket.close()
