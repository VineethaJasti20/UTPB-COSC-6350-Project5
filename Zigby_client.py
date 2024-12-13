import socket
import os
from datetime import datetime
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64


def log(message: str) -> None:
    print(f"[{datetime.now().isoformat()}] CLIENT: {message}")


class ZigBeeClientHandler:

    def __init__(self) -> None:
        # Generate client's ephemeral ECDH key pair
        self._client_private_key = ec.generate_private_key(ec.SECP384R1())
        self.client_public_key = self._client_private_key.public_key()

        # Nonces and session key placeholder
        self.server_nonce: Optional[bytes] = None
        self.client_nonce = os.urandom(32)
        self.session_key: Optional[bytes] = None

    def derive_session_key(self, server_public_key: ec.EllipticCurvePublicKey) -> bytes:

        if self.server_nonce is None:
            raise ValueError("Server nonce must be set before deriving the session key.")

        shared_secret = self._client_private_key.exchange(ec.ECDH(), server_public_key)
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


def main():
    # Connect to the coordinator (server)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    log("Connected to the ZigBee coordinator.")

    zigbee_client = ZigBeeClientHandler()

    # Step 1: Receive server nonce and server public key
    server_data = client_socket.recv(4096)
    zigbee_client.server_nonce = server_data[:32]
    server_pub_key = serialization.load_pem_public_key(server_data[32:])
    log("Received server nonce and public key.")

    # Step 2: Send client nonce and client public key
    client_pub_bytes = zigbee_client.client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(zigbee_client.client_nonce + client_pub_bytes)
    log("Sent client nonce and public key to server.")

    # Step 3: Derive the session key
    zigbee_client.session_key = zigbee_client.derive_session_key(server_pub_key)
    log(f"Session key derived: {zigbee_client.session_key.hex()}")

    # Step 4: Receive initial encrypted message from the server
    encrypted_initial = client_socket.recv(4096).decode('utf-8')
    decrypted_initial = zigbee_client.decrypt_message(encrypted_initial)
    log(f"Received encrypted packet: {encrypted_initial}")
    log(f"Decrypted initial message: {decrypted_initial}")

    # Send encrypted acknowledgment to server
    ack_message = "Client here, secure session confirmed."
    enc_ack = zigbee_client.encrypt_message(ack_message)
    client_socket.sendall(enc_ack.encode('utf-8'))
    log(f"Sent encrypted acknowledgment: {enc_ack}")

    # Engage in further exchanges
    responses_to_send = [
        "Client says: Understood.",
        "Client says: Data transmission is secure.",
        "Client says: Ending session now."
    ]

    for response in responses_to_send:
        # Send encrypted response
        enc_response = zigbee_client.encrypt_message(response)
        client_socket.sendall(enc_response.encode('utf-8'))
        log(f"Sent encrypted message: {enc_response}")
        log(f"Original client message: {response}")

        # Receive server's encrypted reply
        enc_server_reply = client_socket.recv(4096)
        if not enc_server_reply:
            log("No further replies from server.")
            break
        dec_server_reply = zigbee_client.decrypt_message(enc_server_reply.decode('utf-8'))
        log(f"Received encrypted reply: {enc_server_reply.decode('utf-8')}")
        log(f"Decrypted server reply: {dec_server_reply}")

    client_socket.close()
    log("Connection closed.")


if __name__ == "__main__":
    main()
