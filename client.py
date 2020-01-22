import asyncio
import json
import base64
import argparse
import coloredlogs
import logging
import os
import crypto_funcs
import sys

import getpass

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
    datefmt="%m-%d %H:%M:%S",
)
logger = logging.getLogger("root")

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_NEGOTIATE = 4
STATE_DH = 5
STATE_KEY_ROTATION = 6
STATE_VALIDATE_SERVER = 7
STATE_CLIENT_AUTH = 8
STATE_SERVER_AUTH = 9


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop, use_cc):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """
        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ""  # Buffer to receive data chunks

        self.symetric_ciphers = ["AES", "ChaCha20", "3DES"]
        self.cipher_modes = ["GCM", "None", "ECB", "CBC"]
        self.digest_algorithms = ["SHA256", "SHA512", "BLAKE2"]

        self.used_symetric_cipher = None
        self.used_cipher_mode = None
        self.used_digest_algorithm = None

        self.p = None
        self.g = None
        self.private_key = None
        self.shared_key = None
        self.public_key_pem = None

        self.host_name = "127.0.0.1"

        self.rsa_private, self.rsa_public_pem = crypto_funcs.generate_rsa_key()

        self.text_chunks = None
        self.n_of_chunks_done = None

        self.roots = dict()
        self.intermediate_certs = dict()
        self.user_cert = dict()
        self.chain = list()

        self.use_cc = use_cc

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.
        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug("Connected to Server")

        message = {
            "type": "NEGOTIATION_REQ",
            "algorithms": {
                "symetric_ciphers": self.symetric_ciphers,
                "chiper_modes": self.cipher_modes,
                "digest_algorithms": self.digest_algorithms,
            },
        }

        self._send(message)

        self.state = STATE_NEGOTIATE

    def reply_to_request(self, nonce):
        """
        Function that receives a nonce and creates a reply to an Authentication Challenge 
        using credentials given by input
        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.info("Replying to Challenge Authentication")

        rep_message = {"type": "CHALLENGE_REP", "answer": None, "username": None}

        username = input("Username: ")
        password = getpass.getpass("Password: ")

        answer = crypto_funcs.rsa_signing(
            (str(nonce) + password).encode("utf-8"), self.rsa_private
        )
        rep_message["answer"] = base64.b64encode(answer).decode()
        rep_message["username"] = base64.b64encode(username.encode("utf-8")).decode()

        message = crypto_funcs.create_secure_message(
            rep_message,
            self.shared_key,
            self.used_symetric_cipher,
            self.used_cipher_mode,
            self.used_digest_algorithm,
        )

        return message

    def reply_to_request_cc(self, nonce):
        """
        Function that receives a nonce and creates a reply to an Authentication Challenge 
        using credentials given by cc auth.
        :param nonce: The nonce value that is going to be signed.
        :return:
        """
        logger.info("Replying to Challenge Authentication")

        username = input("Username: ")

        rep_message = {"type": "CHALLENGE_REP_CC", "answer": None, "cert": None}
        answer, cert = crypto_funcs.sign_with_cc(nonce)
        rep_message["answer"] = base64.b64encode(answer).decode()
        rep_message["cert"] = base64.b64encode(cert).decode()
        rep_message["username"] = base64.b64encode(username.encode("utf-8")).decode()

        message = crypto_funcs.create_secure_message(
            rep_message,
            self.shared_key,
            self.used_symetric_cipher,
            self.used_cipher_mode,
            self.used_digest_algorithm,
        )

        return message

    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer
        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug("Received: {}".format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception("Could not decode data from client")

        idx = self.buffer.find("\r\n")

        while idx >= 0:  # While there are separators
            frame = self.buffer[: idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[
                idx + 2 :
            ]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find("\r\n")

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning("Buffer to large")
            self.buffer = ""
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame(JSON Object)
        :param frame: The JSON Object to process
        :return:
        """
        logger.debug("Frame: {}".format(frame))
        logger.debug("State: {}".format(self.state))

        try:
            message = json.loads(frame)
        except Exception as e:
            logger.exception("Could not decode the JSON message - {}".format(e))
            self.transport.close()
            return

        mtype = message.get("type", None)

        if mtype == "OK":  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == "NEGOTIATION_REP":
            algs = message["algorithms"]
            self.used_symetric_cipher = algs["symetric_cipher"]
            self.used_cipher_mode = algs["cipher_mode"]
            self.used_digest_algorithm = algs["digest_algorithm"]

            (
                self.p,
                self.g,
                self.private_key,
                self.public_key_pem,
            ) = crypto_funcs.diffie_hellman_client()

            message = {
                "type": "DH_INIT",
                "parameters": {
                    "p": self.p,
                    "g": self.g,
                    "public_key": str(self.public_key_pem, "ISO-8859-1"),
                },
            }
            self._send(message)
            self.state = STATE_DH
            return

        elif mtype == "DH_SERVER_KEY":
            public_key_pem_client = bytes(message["key"], "ISO-8859-1")

            self.shared_key = crypto_funcs.generate_shared_key(
                self.private_key, public_key_pem_client, self.used_digest_algorithm
            )

            if self.state == STATE_KEY_ROTATION:
                self.state = STATE_DATA
                self.send_file(self.file_name, self.n_of_chunks_done)

            elif self.state == STATE_DH:
                self.nonce = os.urandom(16)

                req = {
                    "type": "AUTH_SERVER_REQ",
                    "nonce": base64.b64encode(self.nonce).decode(),
                    "public_pem": base64.b64encode(self.rsa_public_pem).decode(),
                }

                message = crypto_funcs.create_secure_message(
                    req,
                    self.shared_key,
                    self.used_symetric_cipher,
                    self.used_cipher_mode,
                    self.used_digest_algorithm,
                )

                self.state = STATE_SERVER_AUTH
                self._send(message)

            return

        elif mtype == "SECURE_X":
            actual_message = base64.b64decode(message["payload"])
            mac = base64.b64decode(message["mac"])
            if message["iv"] != None:
                iv = base64.b64decode(message["iv"])
            else:
                iv = None
            if message["nonce"] != None:
                nonce = base64.b64decode(message["nonce"])
            else:
                nonce = None
            if message["tag"] != None:
                tag = base64.b64decode(message["tag"])
            else:
                tag = None

            # Verify integrity of the message
            digest = crypto_funcs.generate_mac(
                actual_message, self.shared_key, self.used_digest_algorithm
            )
            if mac != digest:
                logger.warning("The integrity of the message has been compromised")

            else:
                actual_message = crypto_funcs.symmetric_key_decrypt(
                    actual_message,
                    self.shared_key,
                    self.used_symetric_cipher,
                    self.used_cipher_mode,
                    iv,
                    nonce,
                    tag,
                )

                actual_message = actual_message.decode()
                actual_message = actual_message.split("}")[0] + "}"

                message = json.loads(actual_message)
                mtype = message["type"]

                if mtype == "AUTH_SERVER_REP":
                    retVal = self.process_auth_server(message)

                    if not retVal:
                        message = {"type": "SERVER_AUTH_FAILED"}

                        secure_message = crypto_funcs.create_secure_message(
                            message,
                            self.shared_key,
                            self.used_symetric_cipher,
                            self.used_cipher_mode,
                            self.used_digest_algorithm,
                        )

                        self._send(secure_message)

                    else:

                        if self.use_cc:
                            # Request CC Login
                            logger.info("REQUEST LOGIN WITH CC")
                            req_login = {"type": "CHALLENGE_REQ_CC"}

                        else:
                            # Request Login
                            logger.info("REQUEST LOGIN WITH PW")
                            req_login = {"type": "CHALLENGE_REQ"}

                        message = crypto_funcs.create_secure_message(
                            req_login,
                            self.shared_key,
                            self.used_symetric_cipher,
                            self.used_cipher_mode,
                            self.used_digest_algorithm,
                        )

                        self._send(message)

                elif mtype == "CHALLENGE":
                    # Process Challenge
                    logger.info("PROCESING REQUEST CHALLENGE")
                    nonce = base64.b64decode(message["nonce"].encode())

                    rep_message = self.reply_to_request(nonce)

                    self._send(rep_message)

                elif mtype == "CHALLENGE_CC":
                    # Process Challenge with CC
                    logger.info("PROCESING REQUEST CHALLENGE CC")
                    nonce = base64.b64decode(message["nonce"].encode())

                    rep_message = self.reply_to_request_cc(nonce)

                    self._send(rep_message)

                elif mtype == "CHALLENGE_AUTH_REP":
                    if message["status"] == "FAILED":
                        logger.error("User authentication failed.")
                    elif message["status"] == "DENIED":
                        logger.error("User authentication denied.")
                    elif message["status"] == "SUCCESS":
                        logger.info("User authentication sucessful.")

                        if self.n_of_chunks_done is None:
                            open_message = {"type": "OPEN", "file_name": self.file_name}
                            message = crypto_funcs.create_secure_message(
                                open_message,
                                self.shared_key,
                                self.used_symetric_cipher,
                                self.used_cipher_mode,
                                self.used_digest_algorithm,
                            )

                            self._send(message)
                            self.state = STATE_OPEN

                        else:
                            self.state = STATE_DATA
                            self.send_file(self.file_name, self.n_of_chunks_done)

                return

        elif mtype == "ERROR":
            logger.warning(
                "Got error from server: {}".format(message.get("data", None))
            )

        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info("The server closed the connection")
        self.loop.stop()

    def send_file(self, file_name: str, counter=0) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """
        if self.text_chunks is None:
            text = None
            with open(file_name, "rb") as reader:
                text = reader.read()

            if self.used_symetric_cipher == "AES":
                block_size = 16 * 60
            elif self.used_symetric_cipher == "3DES":
                block_size = 8 * 60
            elif self.used_symetric_cipher == "ChaCha20":
                block_size = 16 * 60

            self.text_chunks = [
                text[i : i + block_size] for i in range(0, len(text), block_size)
            ]  # Divide text into chunks

            # Treat empty files:
            if self.text_chunks == []:
                self.text_chunks = [str.encode(" ")]

        sent_packages_counter = (
            counter  # Used to make sure we don't use our keys for too long
        )

        # Send each chunk
        for i in range(sent_packages_counter, len(self.text_chunks)):
            chunk = self.text_chunks[i]
            data_message = {"type": "DATA", "data": None}

            data_message["data"] = base64.b64encode(chunk).decode()

            message = crypto_funcs.create_secure_message(
                data_message,
                self.shared_key,
                self.used_symetric_cipher,
                self.used_cipher_mode,
                self.used_digest_algorithm,
            )

            logger.info("Transfering Chunk")
            self._send(message)

            sent_packages_counter += 1

            if (
                sent_packages_counter % 5000 == 0
            ):  # FIXME: to test video should be > 100 000
                (
                    self.p,
                    self.g,
                    self.private_key,
                    self.public_key_pem,
                ) = crypto_funcs.diffie_hellman_client()

                message = {
                    "type": "DH_KEY_ROTATION",
                    "parameters": {
                        "p": self.p,
                        "g": self.g,
                        "public_key": str(self.public_key_pem, "ISO-8859-1"),
                    },
                }
                self._send(message)
                self.state = STATE_KEY_ROTATION
                self.n_of_chunks_done = sent_packages_counter
                break

        if sent_packages_counter == len(self.text_chunks):
            close_message = {"type": "CLOSE"}
            message = crypto_funcs.create_secure_message(
                close_message,
                self.shared_key,
                self.used_symetric_cipher,
                self.used_cipher_mode,
                self.used_digest_algorithm,
            )
            self._send(message)

            self.text_chunks = None
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + "\r\n").encode()
        self.transport.write(message_b)

    def process_auth_server(self, message):
        """
        Function used to process a Server Authentication Response.
        :param message: The message received from server. 
        :return: True if validated, False otherwise.
        """
        signature = base64.b64decode(message["signature"])
        server_cert_bytes = message["server_cert"].encode("utf-8")
        server_ca_cert_bytes = message["server_root"].encode("utf-8")

        self.server_cert = crypto_funcs.load_certificate_bytes(server_cert_bytes)
        self.server_public_key = self.server_cert.public_key()
        self.server_ca_cert = crypto_funcs.load_certificate_bytes(server_ca_cert_bytes)

        val_signature = crypto_funcs.validate_rsa_signature(
            signature, self.nonce, self.server_public_key
        )
        logger.info(f"Server signature validation: {val_signature}")
        if not val_signature:
            return False

        val_common_name = self.host_name == crypto_funcs.get_common_name(
            self.server_cert
        )
        logger.info(f"Server common_name validation: {val_common_name}")
        if not val_common_name:
            return False

        val_chain = crypto_funcs.validate_server_chain(
            self.server_cert,
            self.server_ca_cert,
            self.intermediate_certs,
            self.roots,
            self.chain,
        )
        logger.info(f"Server chain validation: {val_chain}")
        if not val_chain:
            return False

        logger.info("SERVER VALIDATED!")
        return True


def main():
    parser = argparse.ArgumentParser(description="Sends files to servers.")
    parser.add_argument(
        "-v", action="count", dest="verbose", help="Shows debug messages", default=0
    )
    parser.add_argument(
        "-s",
        type=str,
        nargs=1,
        dest="server",
        default="127.0.0.1",
        help="Server address (default=127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        type=int,
        nargs=1,
        dest="port",
        default=5000,
        help="Server port (default=5000)",
    )
    parser.add_argument("-c", action="count", dest="use_cc", help="use_cc", default=0)

    parser.add_argument(type=str, dest="file_name", help="File to send")

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server
    use_cc = args.use_cc

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info(
        "Sending file: {} to {}:{} LogLevel: {}".format(
            file_name, server, port, level, use_cc
        )
    )

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(
        lambda: ClientProtocol(file_name, loop, use_cc), server, port
    )
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


if __name__ == "__main__":
    main()
