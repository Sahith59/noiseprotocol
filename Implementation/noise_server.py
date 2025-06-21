import socket
import threading
import logging
import struct
import time
from noise_protocol_handler import NoiseProtocolHandler

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('noise_server')

class NoiseServer:
    def __init__(self, host='localhost', port=8000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {client_id: {'socket': socket, 'noise': NoiseProtocolHandler}}
        self.shutdown_flag = threading.Event()

    def start(self):
        """Start the server and listen for connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logger.info(f"Noise Protocol Server started on {self.host}:{self.port}")
            
            # Start accepting connections in a separate thread
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Keep the main thread running until shutdown is signaled
            self.shutdown_flag.wait()
            
        except Exception as e:
            logger.error(f"Server failed to start: {e}")
        finally:
            self.cleanup()

    def accept_connections(self):
        """Accept client connections and handle them in separate threads."""
        try:
            while not self.shutdown_flag.is_set():
                client_socket, client_address = self.server_socket.accept()
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle's algorithm
                logger.info(f"New connection from {client_address}")
                
                # Start a new thread to handle this client
                client_thread = threading.Thread(target=self.handle_client, 
                                               args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            if not self.shutdown_flag.is_set():
                logger.error(f"Error accepting connections: {e}")

    def handle_client(self, client_socket, client_address):
        """Handle a client connection with Noise Protocol handshake and encryption."""
        client_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            # Create a Noise Protocol handler for this client
            noise_handler = NoiseProtocolHandler(is_server=True)
            
            # Store client information
            self.clients[client_id] = {
                'socket': client_socket,
                'noise': noise_handler,
                'handshake_complete': False
            }
            
            # Perform Noise handshake
            if not self.perform_handshake(client_id):
                logger.error(f"Handshake failed with client {client_id}")
                return
            
            logger.info(f"Secure channel established with {client_id}")
            self.clients[client_id]['handshake_complete'] = True
            
            # Exchange encrypted messages
            while not self.shutdown_flag.is_set():
                try:
                    # Receive message length (4 bytes)
                    length_bytes = client_socket.recv(4)
                    if not length_bytes or len(length_bytes) != 4:
                        logger.info(f"Client {client_id} disconnected")
                        break
                    
                    # Unpack message length
                    message_length = struct.unpack('!I', length_bytes)[0]
                    logger.info(f"Received message of length {message_length} from {client_id}")
                    
                    # Receive the encrypted message
                    encrypted_message = b''
                    bytes_remaining = message_length
                    
                    while bytes_remaining > 0:
                        chunk = client_socket.recv(min(4096, bytes_remaining))
                        if not chunk:
                            logger.error(f"Connection closed during message read from {client_id}")
                            break
                        
                        encrypted_message += chunk
                        bytes_remaining -= len(chunk)
                    
                    if len(encrypted_message) != message_length:
                        logger.error(f"Incomplete message from {client_id}: got {len(encrypted_message)}/{message_length} bytes")
                        break
                    
                    # Decrypt the message
                    try:
                        decrypted_message = noise_handler.decrypt(encrypted_message)
                        message_text = decrypted_message.decode('utf-8')
                        logger.info(f"Decrypted message from {client_id}: {message_text}")
                        
                        # Echo back the message (encrypted)
                        response = f"Echo: {message_text}"
                        self.send_encrypted_message(client_id, response)
                        
                    except Exception as e:
                        logger.error(f"Decryption error: {str(e)}")
                        break
                
                except socket.timeout:
                    # Socket timeout, just continue
                    continue
                except Exception as e:
                    logger.error(f"Error handling messages from {client_id}: {str(e)}")
                    break
                
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            # Clean up client resources
            if client_id in self.clients:
                del self.clients[client_id]
            client_socket.close()
            logger.info(f"Connection with {client_id} closed")

    def perform_handshake(self, client_id):
        """Perform the Noise XX Protocol handshake with a client."""
        if client_id not in self.clients:
            return False
        
        client_info = self.clients[client_id]
        client_socket = client_info['socket']
        noise_handler = client_info['noise']
        
        try:
            # Receive client's message1 (e)
            length_bytes = client_socket.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                logger.error(f"Client {client_id} disconnected during handshake")
                return False
            
            message_length = struct.unpack('!I', length_bytes)[0]
            message1 = client_socket.recv(message_length)
            
            if len(message1) != message_length:
                logger.error(f"Incomplete message1 from {client_id}")
                return False
            
            logger.info(f"Server received message1: {len(message1)} bytes")
            
            # Process message1 and generate message2 (e, ee, s, es)
            message2 = noise_handler.handshake_step(message1)
            
            if message2 is None:
                logger.error(f"Failed to generate message2 for {client_id}")
                return False
            
            # Send message2 to client
            logger.info(f"Server sending message2: {len(message2)} bytes")
            message_length = struct.pack('!I', len(message2))
            client_socket.sendall(message_length + message2)
            
            # Receive client's message3 (s, se)
            length_bytes = client_socket.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                logger.error(f"Client {client_id} disconnected before sending message3")
                return False
            
            message_length = struct.unpack('!I', length_bytes)[0]
            message3 = client_socket.recv(message_length)
            
            if len(message3) != message_length:
                logger.error(f"Incomplete message3 from {client_id}")
                return False
            
            logger.info(f"Server received message3: {len(message3)} bytes")
            
            # Process message3 and complete handshake
            noise_handler.handshake_step(message3)
            
            return noise_handler.handshake_complete
            
        except Exception as e:
            logger.error(f"Handshake error with {client_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def send_encrypted_message(self, client_id, message):
        """Send an encrypted message to a client."""
        if client_id not in self.clients:
            logger.error(f"Client {client_id} not found")
            return False
        
        client_info = self.clients[client_id]
        if not client_info['handshake_complete']:
            logger.error(f"Handshake not complete with {client_id}")
            return False
        
        try:
            # Encrypt the message
            encrypted_message = client_info['noise'].encrypt(message)
            
            # Pack message length and send as a single operation
            message_length = struct.pack('!I', len(encrypted_message))
            client_info['socket'].sendall(message_length + encrypted_message)
            logger.info(f"Sent encrypted message to {client_id}: {len(encrypted_message)} bytes")
            return True
            
        except Exception as e:
            logger.error(f"Error sending encrypted message to {client_id}: {e}")
            return False

    def broadcast_encrypted(self, message, exclude=None):
        """Broadcast an encrypted message to all connected clients."""
        for client_id, client_info in list(self.clients.items()):
            if exclude and client_id == exclude:
                continue
                
            if client_info['handshake_complete']:
                self.send_encrypted_message(client_id, message)

    def stop(self):
        """Stop the server gracefully."""
        logger.info("Shutting down Noise Protocol Server...")
        self.shutdown_flag.set()
        
        # Create a dummy connection to unblock accept()
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((self.host, self.port))
        except:
            pass

    def cleanup(self):
        """Clean up server resources."""
        # Close all client connections
        for client_id, client_info in list(self.clients.items()):
            try:
                client_info['socket'].close()
            except:
                pass
        self.clients.clear()
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    server = NoiseServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()