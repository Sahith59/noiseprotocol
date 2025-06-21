"""
Full Noise Protocol implementation for secure communication.
Following the Noise Protocol Framework specification.
"""

import os
import logging
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('noise_protocol')

class NoiseProtocolHandler:
    """Full implementation of Noise Protocol (XX pattern) with ChaCha20-Poly1305."""
    
    def __init__(self, is_server=False, protocol_name="Noise_XX_25519_ChaChaPoly_SHA256"):
        self.is_server = is_server
        self.protocol_name = protocol_name
        
        # Handshake state
        self.handshake_started = False
        self.handshake_complete = False
        self.message_patterns = self._get_message_patterns()
        self.message_pattern_index = 0
        
        # Generate static keypair
        self.static_private = X25519PrivateKey.generate()
        self.static_public = self.static_private.public_key()
        self.static_public_bytes = self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Generate ephemeral keypair
        self.ephemeral_private = X25519PrivateKey.generate()
        self.ephemeral_public = self.ephemeral_private.public_key()
        self.ephemeral_public_bytes = self.ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Remote keys
        self.remote_static_public = None
        self.remote_ephemeral_public = None
        
        # Noise Protocol state
        self.symmetricstate_h = None
        self.symmetricstate_ck = None
        self.sending_key = None
        self.receiving_key = None
        
        # Nonces
        self.send_nonce = 0
        self.receive_nonce = 0
        self.temp_k = None
    
    def _get_message_patterns(self):
        """Return message patterns for XX handshake."""
        # XX handshake pattern:
        # -> e
        # <- e, ee, s, es
        # -> s, se
        if self.is_server:
            return [
                [], # First message (initiator -> responder): e
                ["e", "ee", "s", "es"],  # Second message (responder -> initiator): e, ee, s, es
                []  # Third message (initiator -> responder): s, se
            ]
        else:
            return [
                ["e"],  # First message (initiator -> responder): e
                [],     # Second message (responder -> initiator): e, ee, s, es
                ["s", "se"]  # Third message (initiator -> responder): s, se
            ]
    
    def initialize_symmetricstate(self):
        """Initialize the symmetric state for the handshake."""
        protocol_name_bytes = self.protocol_name.encode('ascii')
        
        if len(protocol_name_bytes) <= 32:
            self.symmetricstate_h = protocol_name_bytes + b'\0' * (32 - len(protocol_name_bytes))
        else:
            self.symmetricstate_h = hashlib.sha256(protocol_name_bytes).digest()
        
        self.symmetricstate_ck = self.symmetricstate_h
    
    def mix_hash(self, data):
        """Mix data into the handshake hash."""
        self.symmetricstate_h = hashlib.sha256(self.symmetricstate_h + data).digest()
    
    def mix_key(self, input_key_material):
        """Mix key material into the symmetric state."""
        output = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=self.symmetricstate_ck,
            info=b'',
        ).derive(input_key_material)
        
        self.symmetricstate_ck = output[:32]
        temp_k = output[32:]
        return temp_k
    
    def encrypt_and_hash(self, plaintext, key=None):
        """Encrypt plaintext and mix ciphertext into the handshake hash."""
        if key is None:
            ciphertext = plaintext
        else:
            nonce = bytes([0] * 12)  # All-zero nonce for handshake
            cipher = ChaCha20Poly1305(key)
            ciphertext = cipher.encrypt(nonce, plaintext, self.symmetricstate_h)
        
        self.mix_hash(ciphertext)
        return ciphertext
    
    def decrypt_and_hash(self, ciphertext, key=None):
        """Decrypt ciphertext and mix ciphertext into the handshake hash."""
        if key is None:
            plaintext = ciphertext
        else:
            nonce = bytes([0] * 12)  # All-zero nonce for handshake
            cipher = ChaCha20Poly1305(key)
            plaintext = cipher.decrypt(nonce, ciphertext, self.symmetricstate_h)
        
        self.mix_hash(ciphertext)
        return plaintext
    
    # In noise_protocol_handler.py
    def dh(self, local_private, remote_public_bytes):
        """Perform Diffie-Hellman key exchange."""
        try:
            # Create X25519 public key from bytes
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
            remote_public = X25519PublicKey.from_public_bytes(remote_public_bytes)
            
            # Calculate shared secret
            shared_secret = local_private.exchange(remote_public)
            logger.debug(f"DH shared secret calculated: {len(shared_secret)} bytes")
            return shared_secret
            
        except Exception as e:
            logger.error(f"DH exchange error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise
    
    def split(self):
        """Split the symmetric state for transport messages."""
        output1 = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=self.symmetricstate_ck,
            info=b'',
        ).derive(b'')
        
        self.sending_key = output1[:32]
        self.receiving_key = output1[32:]
        
        if not self.is_server:
            # Swap keys for client
            self.sending_key, self.receiving_key = self.receiving_key, self.sending_key
        
        logger.info(f"Keys derived - sending: {len(self.sending_key)} bytes, receiving: {len(self.receiving_key)} bytes")
    
    def start_handshake(self):
        """Start the Noise Protocol handshake."""
        logger.info(f"Starting handshake as {'responder' if self.is_server else 'initiator'}")
        self.handshake_started = True
        self.message_pattern_index = 0
        self.initialize_symmetricstate()
    
    # In noise_protocol_handler.py

    def handshake_step(self, message=None):
        """
        Perform a step in the Noise XX handshake.
        """
        if not self.handshake_started:
            self.start_handshake()
        
        if self.handshake_complete:
            logger.info("Handshake already complete")
            return None
        
        logger.info(f"Handshake step: is_server={self.is_server}, step={self.handshake_step_counter}")
        logger.info(f"Incoming message: {None if message is None else len(message)} bytes")
        
        # For server
        if self.is_server:
            if self.handshake_step_counter == 0 and message is not None:
                # Process first message from client (e)
                self.remote_ephemeral_public = message[:32]
                self.mix_hash(self.remote_ephemeral_public)
                
                # Generate response (e, ee, s, es)
                self.handshake_step_counter += 1
                return self.create_outgoing_message(["e", "ee", "s", "es"])
                
            elif self.handshake_step_counter == 1 and message is not None:
                # Process third message from client (s, se)
                # Extract s
                self.remote_static_public = self.decrypt_and_hash(message, self.temp_k)
                
                # Process se
                shared_secret3 = self.dh(self.ephemeral_private, self.remote_static_public)
                self.mix_key(shared_secret3)
                
                # Split for transport
                self.split()
                self.handshake_complete = True
                self.handshake_step_counter += 1
                
                logger.info("Server handshake completed successfully")
                return None
        
        # For client
        else:
            if self.handshake_step_counter == 0:
                # Send initial message (e)
                self.handshake_step_counter += 1
                return self.create_outgoing_message(["e"])
                
            elif self.handshake_step_counter == 1 and message is not None:
                # Process second message from server (e, ee, s, es)
                idx = 0
                
                # Extract e
                self.remote_ephemeral_public = message[:32]
                self.mix_hash(self.remote_ephemeral_public)
                idx += 32
                
                # Process ee
                shared_secret1 = self.dh(self.ephemeral_private, self.remote_ephemeral_public)
                temp_k1 = self.mix_key(shared_secret1)
                
                # Extract s
                encrypted_s = message[idx:]
                self.remote_static_public = self.decrypt_and_hash(encrypted_s, temp_k1)
                
                # Process es
                shared_secret2 = self.dh(self.ephemeral_private, self.remote_static_public)
                self.temp_k = self.mix_key(shared_secret2)
                
                # Generate final message (s, se)
                self.handshake_step_counter += 1
                return self.create_outgoing_message(["s", "se"])
        
        logger.error(f"Unexpected handshake state: is_server={self.is_server}, step={self.handshake_step_counter}")
        return None
    
    def process_incoming_message(self, message):
        """
        Process an incoming handshake message based on the expected pattern.
        """
        try:
            if self.is_server and self.message_pattern_index == 1:  # Server received e
                # Extract e
                self.remote_ephemeral_public = message[:32]
                self.mix_hash(self.remote_ephemeral_public)
                
                # Next message will be from server (e, ee, s, es)
                return self.create_outgoing_message(["e", "ee", "s", "es"])
                
            elif not self.is_server and self.message_pattern_index == 2:  # Client received e, ee, s, es
                idx = 0
                
                # Extract e
                self.remote_ephemeral_public = message[:32]
                self.mix_hash(self.remote_ephemeral_public)
                idx += 32
                
                # Process ee
                shared_secret1 = self.dh(self.ephemeral_private, self.remote_ephemeral_public)
                temp_k1 = self.mix_key(shared_secret1)
                
                # Extract s
                encrypted_s = message[idx:]  # Rest of the message is encrypted s
                self.remote_static_public = self.decrypt_and_hash(encrypted_s, temp_k1)
                
                # Process es
                shared_secret2 = self.dh(self.ephemeral_private, self.remote_static_public)
                self.temp_k = self.mix_key(shared_secret2)
                
                # Next message will be from client (s, se)
                return self.create_outgoing_message(["s", "se"])
                
            elif self.is_server and self.message_pattern_index == 3:  # Server received s, se
                # Extract s
                self.remote_static_public = self.decrypt_and_hash(message, self.temp_k)
                
                # Process se
                shared_secret3 = self.dh(self.ephemeral_private, self.remote_static_public)
                temp_k3 = self.mix_key(shared_secret3)
                
                # Split for transport
                self.split()
                self.handshake_complete = True
                
                return None
        
            logger.error(f"Unexpected message pattern index: {self.message_pattern_index}")
            return None
        except Exception as e:
            logger.error(f"Error processing incoming message: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return None
    
    def create_outgoing_message(self, pattern):
        """
        Create an outgoing handshake message based on the given pattern.
        
        Args:
            pattern (list): The message pattern to use.
            
        Returns:
            bytes: The handshake message.
        """
        message = b''
        
        # Handle specific message patterns based on the XX protocol
        if pattern == ["e"]:  # Client's first message
            # Add e
            message += self.ephemeral_public_bytes
            self.mix_hash(self.ephemeral_public_bytes)
            return message
        
        elif pattern == ["e", "ee", "s", "es"]:  # Server's response to first message
            # Add e
            message += self.ephemeral_public_bytes
            self.mix_hash(self.ephemeral_public_bytes)
            
            # Add ee
            shared_secret1 = self.dh(self.ephemeral_private, self.remote_ephemeral_public)
            temp_k1 = self.mix_key(shared_secret1)
            
            # Add s
            encrypted_s = self.encrypt_and_hash(self.static_public_bytes, temp_k1)
            message += encrypted_s
            
            # Add es
            shared_secret2 = self.dh(self.static_private, self.remote_ephemeral_public)
            temp_k2 = self.mix_key(shared_secret2)
            
            # Save for later use
            self.temp_k = temp_k2
            
            return message
        
        elif pattern == ["s", "se"]:  # Client's final message
            # Add s
            encrypted_s = self.encrypt_and_hash(self.static_public_bytes, self.temp_k)
            message += encrypted_s
            
            # Add se
            shared_secret3 = self.dh(self.static_private, self.remote_ephemeral_public)
            temp_k3 = self.mix_key(shared_secret3)
            
            # Split for transport
            self.split()
            self.handshake_complete = True
            
            return message
        
        logger.error(f"Unexpected outgoing message pattern: {pattern}")
        return None
    
    def encrypt(self, message):
        """
        Encrypt a transport message.
        
        Args:
            message (bytes or str): The message to encrypt.
            
        Returns:
            bytes: The encrypted message.
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake must be complete before encrypting")
        
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            original_size = len(message)
            logger.info(f"Encrypting message of {original_size} bytes with key length {len(self.sending_key)} bytes")
            
            # Get nonce
            nonce = self.send_nonce.to_bytes(12, byteorder='little')
            cipher = ChaCha20Poly1305(self.sending_key)
            ciphertext = cipher.encrypt(nonce, message, b'')
            self.send_nonce += 1
            
            # Log encryption metadata for debugging but return only the ciphertext
            logger.debug(f"Encryption metadata: original_size={original_size}, encrypted_size={len(ciphertext)}, key_id={self.sending_key[-4:].hex()}")
            
            # Return only the ciphertext bytes to avoid breaking existing code
            return ciphertext
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise


    def decrypt(self, ciphertext):
        """
        Decrypt a transport message.
        
        Args:
            ciphertext (bytes): The encrypted message.
            
        Returns:
            bytes: The decrypted message.
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake must be complete before decrypting")
        
        try:
            logger.info(f"Decrypting message of {len(ciphertext)} bytes with key length {len(self.receiving_key)} bytes")
            
            nonce = self.receive_nonce.to_bytes(12, byteorder='little')
            cipher = ChaCha20Poly1305(self.receiving_key)
            plaintext = cipher.decrypt(nonce, ciphertext, b'')
            self.receive_nonce += 1
            
            # Log decryption metadata but return only the plaintext
            logger.debug(f"Decryption metadata: encrypted_size={len(ciphertext)}, decrypted_size={len(plaintext)}, key_id={self.receiving_key[-4:].hex()}")
            
            return plaintext
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise

        # Add this to the NoiseProtocolHandler class

    def start_handshake(self):
        """Start the Noise Protocol handshake."""
        logger.info(f"Starting handshake as {'responder' if self.is_server else 'initiator'}")
        self.handshake_started = True
        self.handshake_step_counter = 0
        self.initialize_symmetricstate()
        
        # Debug log the initial state
        logger.debug(f"Initial hash: {self.symmetricstate_h.hex()}")