import socket
import logging
import time

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('test_client')

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    try:
        client_socket.connect(('localhost', 8000))
        logger.info("Connected to server")
        
        # Receive the server's hello message
        server_hello = client_socket.recv(1024)
        logger.info(f"Received from server: {server_hello}")
        
        # Send a response
        client_socket.sendall(b'CLIENT_RESPONSE')
        logger.info("Sent response to server")
        
        # Receive acknowledgment
        ack = client_socket.recv(1024)
        logger.info(f"Received ack: {ack}")
        
        logger.info("Communication test successful!")
        
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()