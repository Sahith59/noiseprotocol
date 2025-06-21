import socket
import threading
import logging
import struct
import time
import json
import argparse
import sys
from noise_protocol_handler import NoiseProtocolHandler

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('noise_chat_client')

class NoiseChatClient:
    def __init__(self, host='localhost', port=8000, username=None):
        self.host = host
        self.port = port
        self.username = username or f"User_{int(time.time()) % 10000}"
        self.client_socket = None
        self.connected = False
        self.shutdown_flag = threading.Event()
        self.receive_thread = None
        self.noise_handler = None
        self.handshake_complete = False
        self.message_queue = []  # Queue of messages to display

    def connect(self):
        """Connect to the server and establish a secure channel using Noise Protocol."""
        try:
            # Create socket connection
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
                
                # Set username
                self.set_username(self.username)
                
                return True
            else:
                logger.error("Failed to establish secure channel")
                self.disconnect()
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self.disconnect()
            return False
        

    def join_room(self, room_id):
        """Join a chat room."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        message = {
            "type": "join_room",
            "room_id": room_id
        }
    
        return self.send_message(message)
    
    def create_room(self, room_id, room_name, description=""):
        """Create a new chat room."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        message = {
            "type": "create_room",
            "room_id": room_id,
            "room_name": room_name,
            "description": description
        }
        
        return self.send_message(message)
        
    def leave_room(self, room_id):
        """Leave a chat room."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        message = {
            "type": "leave_room",
            "room_id": room_id
        }
        
        return self.send_message(message)
        
    def list_rooms(self):
        """Request a list of available chat rooms."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        message = {
            "type": "list_rooms"
        }
        
        return self.send_message(message)
        
    def send_room_message(self, room_id, content):
        """Send a message to a specific chat room."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        message = {
            "type": "chat_message",
            "room_id": room_id,
            "content": content
        }
        
        return self.send_message(message)

    def perform_handshake(self):
        """Perform the Noise Protocol handshake with the server."""
        try:
            # Generate message1
            message1 = self.noise_handler.handshake_step(None)
            
            if message1 is None:
                logger.error("Failed to generate initial handshake message")
                return False
            
            logger.info(f"Sending message1 of {len(message1)} bytes")
            message_length = struct.pack('!I', len(message1))
            self.client_socket.sendall(message_length + message1)
            
            # Receive message2 from server
            length_bytes = self.client_socket.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                logger.error("Server disconnected during handshake")
                return False
            
            message_length = struct.unpack('!I', length_bytes)[0]
            
            if message_length > 0:
                message2 = self.client_socket.recv(message_length)
                if len(message2) != message_length:
                    logger.error("Incomplete message received from server")
                    return False
                logger.info(f"Received message2 of {len(message2)} bytes")
            else:
                message2 = b''
                logger.info("Received empty message2")
            
            # Process message2 and generate message3 if needed
            message3 = self.noise_handler.handshake_step(message2)
            
            # If we need to send another message
            if message3 is not None:
                logger.info(f"Sending message3 of {len(message3)} bytes")
                message_length = struct.pack('!I', len(message3))
                self.client_socket.sendall(message_length + message3)
            
            return self.noise_handler.handshake_complete
            
        except Exception as e:
            logger.error(f"Handshake error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    # In noise_chat_client.py receive_messages method

    def receive_messages(self):
        """Receive and decrypt messages from the server."""
        try:
            while not self.shutdown_flag.is_set() and self.connected:
                # Receive message length (4 bytes)
                length_bytes = self.client_socket.recv(4)
                if not length_bytes or len(length_bytes) != 4:
                    logger.info("Disconnected from server")
                    self.connected = False
                    print("\nDisconnected from server. Press Enter to exit.")
                    break
                
                # Unpack message length
                message_length = struct.unpack('!I', length_bytes)[0]
                
                # Receive the encrypted message
                encrypted_message = self.client_socket.recv(message_length)
                if len(encrypted_message) != message_length:
                    logger.error("Incomplete message received from server")
                    break
                
                # Decrypt the message and capture metadata
                try:
                    decryption_result = self.noise_handler.decrypt(encrypted_message)
                    
                    # Handle both dictionary return and direct bytes
                    if isinstance(decryption_result, dict) and 'plaintext' in decryption_result:
                        decrypted_message = decryption_result['plaintext']
                        decryption_metadata = decryption_result.get('metadata', {})
                    else:
                        decrypted_message = decryption_result
                        decryption_metadata = {}
                    
                    # Convert to string if it's bytes
                    if isinstance(decrypted_message, bytes):
                        message_text = decrypted_message.decode('utf-8')
                    else:
                        message_text = str(decrypted_message)
                    
                    # Parse as JSON if possible
                    try:
                        message_data = json.loads(message_text)
                        
                        # Add decryption metadata
                        if isinstance(message_data, dict):
                            message_data['decryption'] = decryption_metadata
                        
                        # Process the message based on its type
                        self.process_message(message_data)
                        
                    except json.JSONDecodeError:
                        logger.error("Invalid JSON received")
                    
                except Exception as e:
                    logger.error(f"Message processing error: {e}")
                    break
                    
        except Exception as e:
            if not self.shutdown_flag.is_set():
                logger.error(f"Error receiving messages: {e}")
            self.connected = False
            print("\nConnection error. Press Enter to exit.")

    def process_message(self, message_data):
        """Process a message from the server."""
        if 'type' not in message_data:
            logger.warning("Message missing 'type' field")
            return
            
        message_type = message_data['type']
        
        if message_type == 'chat_message':
            # Handle chat message
            if 'username' in message_data and 'content' in message_data:
                room_prefix = ""
                if 'room_name' in message_data and message_data.get('room_id', 'main') != 'main':
                    room_prefix = f"[{message_data['room_name']}] "
                print(f"\n{room_prefix}[{message_data['username']}] {message_data['content']}")
                print("> ", end='', flush=True)
        
        elif message_type == 'room_list':
            # Handle room list
            if 'rooms' in message_data:
                print("\nAvailable Rooms:")
                for room in message_data['rooms']:
                    print(f"  - {room['name']} (ID: {room['id']}, Members: {room['member_count']})")
                    if room.get('description'):
                        print(f"    {room['description']}")
                print("> ", end='', flush=True)
        
        elif message_type == 'room_joined':
            # Handle room join confirmation
            if 'room_name' in message_data:
                print(f"\n[System] You joined the room: {message_data['room_name']}")
                print("> ", end='', flush=True)
        
        elif message_type == 'user_joined_room':
            # Handle user joined room notification
            if 'username' in message_data and 'room_name' in message_data:
                print(f"\n[System] {message_data['username']} has joined the room: {message_data['room_name']}")
                print("> ", end='', flush=True)
        
        elif message_type == 'user_left_room':
            # Handle user left room notification
            if 'username' in message_data and 'room_name' in message_data:
                print(f"\n[System] {message_data['username']} has left the room: {message_data['room_name']}")
                print("> ", end='', flush=True)
    
    # Handle other message types as before...

    def set_username(self, username):
        """Set or change the username."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
            
        try:
            message = {
                "type": "set_username",
                "username": username
            }
            return self.send_message(message)
        except Exception as e:
            logger.error(f"Failed to set username: {e}")
            return False

    def send_chat_message(self, content):
        """Send a chat message."""
        if not content.strip():
            return {'success': False, 'message': 'Empty content'}
            
        message = {
            "type": "chat_message",
            "content": content
        }
        
        return self.send_message(message)
    
    def send_message_with_metadata(self, message):
        """Send a message and return encryption metadata."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        try:
            # Convert message to JSON if it's a dict
            if isinstance(message, dict):
                message_json = json.dumps(message)
            else:
                message_json = message
                
            # Encrypt the message and get metadata
            encryption_data = self.noise_handler.encrypt(message_json)
            ciphertext = encryption_data['ciphertext']
            metadata = encryption_data['metadata']
            
            # Pack message length and send
            message_length = struct.pack('!I', len(ciphertext))
            self.client_socket.sendall(message_length + ciphertext)
            
            return {
                'success': True,
                'metadata': metadata,
                'original_message': message
            }
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def send_ping(self):
        """Send a ping to measure latency."""
        message = {
            "type": "ping",
            "timestamp": time.time()
        }
        return self.send_message(message)

    def send_message(self, message):
        """Encrypt and send a message to the server."""
        if not self.connected or not self.handshake_complete:
            logger.error("Not connected or handshake not complete")
            return False
        
        try:
            # Convert message to JSON if it's a dict
            if isinstance(message, dict):
                message = json.dumps(message)
                
            # Make sure message is a string before encrypting
            if not isinstance(message, str) and not isinstance(message, bytes):
                message = str(message)
                
            # Log original message for debugging
            logger.info(f"Encrypting message: {message}")
            
            # Store original message and size
            original_message = message
            original_size = len(message.encode('utf-8') if isinstance(message, str) else message)
            
            # Encrypt the message
            encrypted_message = self.noise_handler.encrypt(message)
            encrypted_size = len(encrypted_message)

            # Capture metadata for UI
            key_id = self.noise_handler.sending_key.hex()  # Get full key ID
            encrypted_hex = encrypted_message.hex()  # Get full hex representation
            
            # Pack message length and send
            message_length = struct.pack('!I', len(encrypted_message))
            logger.info(f"Sending message of {len(encrypted_message)} bytes")
            self.client_socket.sendall(message_length + encrypted_message)
            
            # Return encryption details for UI display
            return {
                'success': True,
                'metadata': {
                    'original_size': original_size,
                    'encrypted_size': encrypted_size,
                    'key_id': self.noise_handler.sending_key[-4:].hex(),
                    'encrypted_hex': encrypted_message[:20].hex() + "..." if encrypted_message else "",
                    'full_encrypted_hex': encrypted_message.hex() if encrypted_message else ""
                },
                'original_message': original_message
            }
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.connected = False
            return {'success': False, 'error': str(e)}

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

    def start_chat(self):
        """Start the chat client."""
        if not self.connect():
            print("Failed to connect to the chat server.")
            return
            
        print(f"Connected to chat server as {self.username}")
        print("Commands: /nick <new_name>, /ping, /quit")
        print("Type your message and press Enter to send.")
        
        try:
            while self.connected and not self.shutdown_flag.is_set():
                user_input = input("> ")
                
                if user_input.lower() == '/quit':
                    break
                elif user_input.lower() == '/ping':
                    self.send_ping()
                elif user_input.lower().startswith('/nick '):
                    new_username = user_input[6:].strip()
                    if new_username:
                        self.username = new_username
                        self.set_username(new_username)
                    else:
                        print("Usage: /nick <new_username>")
                else:
                    self.send_chat_message(user_input)
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Noise Protocol Chat Client')
    parser.add_argument('--host', default='localhost', help='Server host to connect to')
    parser.add_argument('--port', type=int, default=8000, help='Server port to connect to')
    parser.add_argument('--username', help='Your chat username')
    
    args = parser.parse_args()
    
    client = NoiseChatClient(host=args.host, port=args.port, username=args.username)
    client.start_chat()