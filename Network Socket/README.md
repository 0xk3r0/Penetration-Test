# TCP Connection Server-Client

This project consists of a simple TCP Connection Server and Client implemented in Python. The server listens for incoming connections from clients and echoes back any messages received from them. It's a basic example of client-server communication using sockets.

## Usage

### Server

The server script (`server.py`) creates a TCP socket, binds it to a specified IP address and port, listens for incoming connections, and echoes back any messages received from clients.

To run the server:
1. Open a terminal.
2. Navigate to the directory containing `server.py`.
3. Run the following command:
- The server will start and display a message indicating that it's listening for connections.

### Client

The client script (`client.py`) connects to the server, prompts the user to enter a message, sends the message to the server, and displays the echoed message received from the server.

To run the client:
1. Open another terminal.
2. Navigate to the directory containing `client.py`.
3. Run the following command:
- The client will connect to the server and prompt you to enter a message.
- Type your message (or type 'exit' to quit).
- If you type 'exit', the client will close the connection and exit.
- Otherwise, the client will send the message to the server, and the server will echo it back.
- The echoed message will be displayed in the client terminal.

## Requirements

- Python 3.x
- Socket Library:
  ```
  pip install sockets
  ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
