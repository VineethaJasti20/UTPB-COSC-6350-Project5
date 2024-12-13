import socket
import threading
import os
from datetime import datetime
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64


def log(message: str) -> None:
    print(f"[{datetime.now().isoformat()}] SERVER: {message}")


class ZigBeeServerHandler:

    def __init__(self) -> None:
        # Generate server's ephemeral ECDH key pair
        self._server_private_key = ec.generate_private_key(ec.SECP384R1())
        self.server_public_key = self._server_private_key.public_key()

        # Nonces used in the handshake to derive the key
        self.server_nonce = os.urandom(32)
        self.client_nonce: Optional[bytes] = None
        self.session_key: Optional[bytes] = None

    def derive_session_key(self, client_public_key: ec.EllipticCurvePublicKey) -> bytes:

        if self.client_nonce is None:
            raise ValueError("Client nonce must be set before deriving the session key.")

        # Perform ECDH to get the shared secret
        shared_secret = self._server_private_key.exchange(ec.ECDH(), client_public_key)

        # Use HKDF to derive a 32-byte session key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.server_nonce + self.client_nonce
        )
        return hkdf.derive(shared_secret)

    def encrypt_message(self, plaintext: str) -> str:

        if self.session_key is None:
            raise ValueError("No session key available for encryption.")

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

        # Pack IV, Tag, Ciphertext together and encode as base64
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')

    def decrypt_message(self, encrypted_message: str) -> str:

        if self.session_key is None:
            raise ValueError("No session key available for decryption.")

        decoded = base64.b64decode(encrypted_message.encode('utf-8'))
        iv = decoded[:16]
        tag = decoded[16:32]
        ciphertext = decoded[32:]

        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')


def handle_client_connection(client_socket: socket.socket, client_address, zigbee_server: ZigBeeServerHandler):
    try:
        log(f"Client connected from {client_address}")

        # Step 1: Send server nonce and public key to client
        server_pub_bytes = zigbee_server.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(zigbee_server.server_nonce + server_pub_bytes)
        log("Server nonce and public key sent to client.")

        # Step 2: Receive client nonce and public key
        data = client_socket.recv(4096)
        if not data:
            log("No data received from client. Closing connection.")
            return
        zigbee_server.client_nonce = data[:32]
        client_pub_key = serialization.load_pem_public_key(data[32:])
        log("Client nonce and public key received.")

        # Step 3: Derive session key
        zigbee_server.session_key = zigbee_server.derive_session_key(client_pub_key)
        log(f"Session key derived: {zigbee_server.session_key.hex()}")

        # Step 4: Send an initial encrypted welcome message
        initial_message = "Hello! This is the ZigBee coordinator, handshake complete."
        encrypted_init = zigbee_server.encrypt_message(initial_message)
        client_socket.sendall(encrypted_init.encode('utf-8'))
        log(f"Initial encrypted message sent: {encrypted_init}")

        # Step 5: Receive and decrypt client's acknowledgement
        encrypted_ack = client_socket.recv(4096).decode('utf-8')
        if encrypted_ack:
            decrypted_ack = zigbee_server.decrypt_message(encrypted_ack)
            log(f"Received encrypted response: {encrypted_ack}")
            log(f"Decrypted client response: {decrypted_ack}")
        else:
            log("No acknowledgement received from client.")

        # Exchange a few messages back and forth
        messages_to_send = [
            "Coordinator says: You can trust this channel now.",
            "Coordinator says: Let's exchange data securely.",
            "Coordinator says: This concludes the demonstration."
        ]

        for msg in messages_to_send:
            # Send encrypted message
            enc_msg = zigbee_server.encrypt_message(msg)
            client_socket.sendall(enc_msg.encode('utf-8'))
            log(f"Sent encrypted packet: {enc_msg}")

            # Receive response from client
            enc_response = client_socket.recv(4096)
            if not enc_response:
                log("No further response from client. Ending communication.")
                break
            dec_response = zigbee_server.decrypt_message(enc_response.decode('utf-8'))
            log(f"Received encrypted packet from client: {enc_response.decode('utf-8')}")
            log(f"Decrypted client message: {dec_response}")

    except Exception as e:
        log(f"Error while handling client {client_address}: {e}")
    finally:
        client_socket.close()
        log(f"Connection closed with {client_address}")


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    log("ZigBee-like coordinator listening on 0.0.0.0:12345")

    while True:
        client_sock, client_addr = server_socket.accept()
        zigbee_server = ZigBeeServerHandler()
        thread = threading.Thread(target=handle_client_connection, args=(client_sock, client_addr, zigbee_server))
        thread.start()


if __name__ == "__main__":
    main()
