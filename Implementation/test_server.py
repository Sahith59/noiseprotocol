import socket
import threading
import logging
import struct

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('test_server')

def handle_client(client_socket, client_address):
    try:
        # Just send a simple message first
        client_socket.sendall(b'SERVER_HELLO')
        
        # Receive the client's response
        response = client_socket.recv(1024)
        logger.info(f"Received from client: {response}")
        
        # Send acknowledgment
        client_socket.sendall(b'RECEIVED_OK')
        
    except Exception as e:
        logger.error(f"Error handling client: {e}")
    finally:
        client_socket.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', 8000))
        server_socket.listen(5)
        logger.info("Test server started on 0.0.0.0:8000")
        
        while True:
            client_socket, client_address = server_socket.accept()
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            logger.info(f"New connection from {client_address}")
            
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()