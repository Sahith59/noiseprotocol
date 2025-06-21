import socket
import threading
import logging
import struct
import time
import json
from noise_protocol_handler import NoiseProtocolHandler

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('noise_client')

class NoiseClient:
    def __init__(self, host='localhost', port=8000):
        self.host = host
        self.port = port
        self.client_socket = None
        self.connected = False
        self.shutdown_flag = threading.Event()
        self.receive_thread = None
        self.noise_handler = None
        self.handshake_complete = False

    def connect(self):
        """Connect to the server and establish a secure channel using Noise Protocol."""
        try:
            # Create socket connection
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle's algorithm
            self.client_socket.connect((self.host, self.port))
            self.connected = True
            logger.info(f"Connected to server at {self.host}:{self.port}")
            
            # Initialize Noise Protocol handler
            self.noise_handler = NoiseProtocolHandler(is_server=False)
            
            # Perform Noise handshake
            if self.perform_handshake():
                logger.info("Secure channel established with server")
                self.handshake_complete = True
                
                # Start receiving encrypted messages
                self.receive_thread = threading.Thread(target=self.receive_messages)
                self.receive_thread.daemon = True
                self.receive_thread.start()
                
                return True
            else:
                logger.error("Failed to establish secure channel")
                self.disconnect()
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self.disconnect()
            return False

    def perform_handshake(self):
        """Perform the Noise XX Protocol handshake with the server."""
        try:
            # Start handshake
            message1 = self.noise_handler.handshake_step(None)  # First message (e)
            
            if message1 is None:
                logger.error("Failed to generate initial handshake message")
                return False
            
            logger.info(f"Client sending initial message: {len(message1)} bytes")
            message_length = struct.pack('!I', len(message1))
            self.client_socket.sendall(message_length + message1)
            
            # Receive server's message2 (e, ee, s, es)
            length_bytes = self.client_socket.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                logger.error("Server disconnected during handshake")
                return False
            
            message_length = struct.unpack('!I', length_bytes)[0]
            message2 = self.client_socket.recv(message_length)
            
            if len(message2) != message_length:
                logger.error("Incomplete handshake message from server")
                return False
            
            logger.info(f"Client received server message2: {len(message2)} bytes")
            
            # Process message2 and generate message3 (s, se)
            message3 = self.noise_handler.handshake_step(message2)
            
            if message3 is not None:
                # Send message3 to server
                logger.info(f"Client sending message3: {len(message3)} bytes")
                message_length = struct.pack('!I', len(message3))
                self.client_socket.sendall(message_length + message3)
            
            return self.noise_handler.handshake_complete
        
        except Exception as e:
            logger.error(f"Handshake error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def receive_messages(self):
        """Receive and decrypt messages from the server."""
        try:
            while not self.shutdown_flag.is_set() and self.connected:
                try:
                    # Receive message length (4 bytes)
                    length_bytes = self.client_socket.recv(4)
                    if not length_bytes or len(length_bytes) != 4:
                        logger.info("Disconnected from server")
                        self.connected = False
                        break
                    
                    # Unpack message length
                    message_length = struct.unpack('!I', length_bytes)[0]
                    logger.info(f"Received message with length: {message_length}")
                    
                    # Receive the encrypted message
                    encrypted_message = b''
                    bytes_remaining = message_length
                    
                    while bytes_remaining > 0:
                        chunk = self.client_socket.recv(min(4096, bytes_remaining))
                        if not chunk:
                            logger.error("Connection closed while receiving message")
                            self.connected = False
                            break
                        
                        encrypted_message += chunk
                        bytes_remaining -= len(chunk)
                    
                    if len(encrypted_message) != message_length:
                        logger.error(f"Incomplete message received: got {len(encrypted_message)}/{message_length} bytes")
                        break
                    
                    # Decrypt the message
                    try:
                        decrypted_message = self.noise_handler.decrypt(encrypted_message)
                        message_text = decrypted_message.decode('utf-8')
                        logger.info(f"Received from server: {message_text}")
                        print(f"\nReceived: {message_text}")
                        print("> ", end='', flush=True)
                        
                    except Exception as e:
                        logger.error(f"Decryption error: {str(e)}")
                        break
                    
                except socket.timeout:
                    # Socket timeout, just continue
                    continue
                except Exception as e:
                    if not self.shutdown_flag.is_set():
                        logger.error(f"Error receiving messages: {str(e)}")
                    self.connected = False
                    break
                    
        except Exception as e:
            if not self.shutdown_flag.is_set():
                logger.error(f"Error in receive loop: {str(e)}")
            self.connected = False

    def send_message(self, message):
        """Encrypt and send a message to the server."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        try:
            logger.info(f"Sending message: {message}")
            
            # Encrypt the message
            encrypted_message = self.noise_handler.encrypt(message)
            
            # Pack message length and send as a single operation
            message_length = struct.pack('!I', len(encrypted_message))
            self.client_socket.sendall(message_length + encrypted_message)
            logger.info(f"Sent encrypted message: {len(encrypted_message)} bytes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message: {str(e)}")
            self.connected = False
            return False

    def disconnect(self):
        """Disconnect from the server."""
        logger.info("Disconnecting from server...")
        self.shutdown_flag.set()
        
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        
        self.connected = False
        
        # Wait for receive thread to terminate
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=1.0)
        
        logger.info("Disconnected")

    def reset(self):
        """Reset the client for a new connection."""
        if self.connected:
            self.disconnect()
        
        self.noise_handler = None
        self.handshake_complete = False
        self.shutdown_flag.clear()

if __name__ == "__main__":
    client = NoiseClient()
    if client.connect():
        try:
            # Simple test: send encrypted messages
            for i in range(5):
                message = f"Secure test message {i+1}"
                if client.send_message(message):
                    logger.info(f"Sent encrypted: {message}")
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            client.disconnect()