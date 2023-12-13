import socket

def send_file_to_client(host, port, file_path):
    # create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind the socket to a public host and port
    server_socket.bind((host, port))

    # listen for incoming connections
    server_socket.listen()

    # print status message
    print(f'Server listening on {host}:{port}')

    # accept a connection from a client
    (client_socket, client_address) = server_socket.accept()
    print(f'Accepted connection from {client_address[0]}:{client_address[1]}')

    # open the file in binary mode
    with open(file_path, 'rb') as file:
        # send the file
        client_socket.sendfile(file)

    # close client and server sockets
    client_socket.close()
    server_socket.close()
    print("File sent successfully.")

def receive_file_from_server(host, port, file_path):
    # create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connection to hostname on the port.
    client_socket.connect((host, port))

    # print status message
    print(f'Connected to server at {host}:{port}')

    # receive data from the server and write it to a file
    with open(file_path, 'wb') as file:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            file.write(data)

    # print completion message
    print(f"File received successfully and saved at {file_path}")

    # close the client socket
    client_socket.close()
    
   
























