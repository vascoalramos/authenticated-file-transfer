import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
import crypto_funcs
import csv

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

# GLOBAL
storage_dir = "files"


class ClientHandler(asyncio.Protocol):
    def __init__(self, signal):
        """
		Default constructor
		"""
        self.signal = signal
        self.state = STATE_CONNECT
        self.file = None
        self.file_name = None
        self.file_path = None
        self.storage_dir = storage_dir
        self.buffer = ""
        self.peername = ""

        self.symetric_ciphers = ["AES", "3DES", "ChaCha20"]
        self.cipher_modes = ["ECB", "CBC", "GCM", "None"]
        self.digest_algorithms = ["SHA256", "SHA512", "BLAKE2"]

        self.used_symetric_cipher = None
        self.used_cipher_mode = None
        self.used_digest_algorithm = None

        self.p = None
        self.g = None
        self.private_key = None
        self.shared_key = None
        self.public_key_pem = None

        self.rsa_private, self.rsa_public_pem = crypto_funcs.generate_rsa_key()
        self.client_public_pem = None

        self.nonce = None

        self.roots = dict()
        self.intermediate_certs = dict()
        self.user_cert = dict()
        self.chain = list()

    def connection_made(self, transport) -> None:
        """
		Called when a client connects.
		:param transport: The transport stream to use with this client
		:return:
		"""
        self.peername = transport.get_extra_info("peername")
        logger.info("\n\nConnection from {}".format(self.peername))
        self.transport = transport
        self.state = STATE_CONNECT

    def data_received(self, data: bytes) -> None:
        """
		Called when data is received from the client.
		Stores the data in the buffer.
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
		Called when a frame (JSON Object) is extracted.
		:param frame: The JSON object to process
		:return:
		"""
        logger.debug("Frame: {}".format(frame))

        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode JSON message: {}".format(frame))
            self.transport.close()
            return

        mtype = message.get("type", "").upper()

        if mtype == "SECURE_X":
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
                if self.file_path != None:  # If we created a file delete it!
                    os.remove(self.file_path)
                logger.warning("The integrity of the message has been compromised")
                ret = False
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

                if mtype == "DATA":
                    ret = self.process_data(message)
                    self.state = STATE_DATA

                elif mtype == "OPEN":
                    ret = self.process_open(message)
                    self.state = STATE_OPEN

                elif mtype == "CLOSE":
                    ret = self.process_close(message)

                elif mtype == "AUTH_SERVER_REQ":
                    self.client_public_pem = base64.b64decode(message["public_pem"])
                    ret = self.process_auth_server(message)
                    self.state = STATE_SERVER_AUTH

                elif mtype == "SERVER_AUTH_FAILED":
                    logger.warning("Server Authentication failed!")
                    ret = False

                elif mtype == "CHALLENGE_REQ":
                    logger.info("SENDING CHALLENGE")

                    ret = self.process_challenge_req()

                elif mtype == "CHALLENGE_REQ_CC":
                    logger.info("SENDING CHALLENGE WITH CC")
                    ret = self.process_challenge_req_cc()
                    self.state = STATE_CLIENT_AUTH

                elif mtype == "CHALLENGE_REP":
                    logger.info("VALIDATING CHALLENGE REPLY")

                    ret = self.process_challenge_rep(message)

                elif mtype == "CHALLENGE_REP_CC":
                    logger.info("VALIDATING CC CHALLENGE REPLY")
                    ret = self.process_challenge_rep_cc(message)

                else:
                    ret = False

        elif mtype == "NEGOTIATION_REQ":
            ret = self.process_negotiation(message)
            self.state = STATE_NEGOTIATE

        elif mtype == "DH_INIT":
            ret = self.process_dh_init(message)
            self.state = STATE_DH

        elif mtype == "DH_KEY_ROTATION":
            ret = self.process_dh_init(message)
            self.state = STATE_KEY_ROTATION

        else:
            logger.warning("Invalid message type: {}".format(message["type"]))
            ret = False

        if not ret:
            try:
                self._send({"type": "ERROR", "message": "See server"})
            except:
                pass  # Silently ignore

            logger.info("Closing transport")
            if self.file is not None:
                self.file.close()
                self.file = None

            self.state = STATE_CLOSE
            self.transport.close()

    def process_challenge_req(self):
        """
		Function used to create a challenge for the Client to Authenticate itself using a password
        :param message: The message that came from the client (used to get the client's response)
		:return True: Authentication validated
        :return False: Authentication failed or denied
		"""

        self.nonce = os.urandom(16)
        challenge_message = {
            "type": "CHALLENGE",
            "nonce": base64.b64encode(self.nonce).decode(),
        }

        message = crypto_funcs.create_secure_message(
            challenge_message,
            self.shared_key,
            self.used_symetric_cipher,
            self.used_cipher_mode,
            self.used_digest_algorithm,
        )
        self.state = STATE_CLIENT_AUTH
        self._send(message)

        return True

    def process_challenge_rep(self, message):
        """
		Function used to process a Client's response to the Client Authentication using a password
        :param message: The message that came from the client (used to get the client's response)
		:return True: Authentication validated
        :return False: Authentication failed or denied
		"""
        answer = base64.b64decode(message["answer"])

        username = base64.b64decode(message["username"]).decode()

        validation = self.validate_login(username, answer)

        if not validation:
            return False
        else:
            logger.info("ACCEPTING VALIDATION")

            rep = {"type": "CHALLENGE_AUTH_REP", "status": "SUCCESS"}

            message = crypto_funcs.create_secure_message(
                rep,
                self.shared_key,
                self.used_symetric_cipher,
                self.used_cipher_mode,
                self.used_digest_algorithm,
            )

            self._send(message)

            return True

    def process_challenge_req_cc(self):
        """
		Function used to create a challenge for the Client to Authenticate itself using the CC
        :param message: The message that came from the client (used to get the client's response)
		:return True: Authentication validated
        :return False: Authentication failed or denied
		"""
        self.nonce = os.urandom(16)
        challenge_message = {
            "type": "CHALLENGE_CC",
            "nonce": base64.b64encode(self.nonce).decode(),
        }

        message = crypto_funcs.create_secure_message(
            challenge_message,
            self.shared_key,
            self.used_symetric_cipher,
            self.used_cipher_mode,
            self.used_digest_algorithm,
        )

        self._send(message)

        return True

    def process_challenge_rep_cc(self, message):
        """
		Function used to process a Client's response to the Client Authentication using the CC
        :param message: The message that came from the client (used to get the client's response)
		:return True: Authentication validated
        :return False: Authentication failed or denied
		"""
        logger.info("VALIDATING REPLY")
        answer = base64.b64decode(message["answer"])

        cert_bytes = base64.b64decode(message["cert"]).decode()

        username = base64.b64decode(message["username"]).decode()
        with open("credentials_db/users.csv") as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=";")

            line_count = 0
            user_password = None
            user_permissions = None
            for row in csv_reader:
                if line_count == 0:  # Ignore header row
                    line_count += 1
                    continue

                else:
                    if row[0] == username:  # We found our username
                        user_password = row[1]
                        user_permissions = row[3]
                        break

                line_count += 1

            if user_password is not None:  # If we found our user
                if user_permissions != "t":

                    rep = {"type": "CHALLENGE_AUTH_REP", "status": "DENIED"}

                    message = crypto_funcs.create_secure_message(
                        rep,
                        self.shared_key,
                        self.used_symetric_cipher,
                        self.used_cipher_mode,
                        self.used_digest_algorithm,
                    )

                    self._send(message)

                    return False

                cert = crypto_funcs.load_certificate_bytes(cert_bytes.encode("utf-8"))

                validation = crypto_funcs.validate_cc_signature(
                    answer, self.nonce, cert.public_key()
                )

                if not validation:
                    rep = {"type": "CHALLENGE_AUTH_REP", "status": "FAILED"}

                    message = crypto_funcs.create_secure_message(
                        rep,
                        self.shared_key,
                        self.used_symetric_cipher,
                        self.used_cipher_mode,
                        self.used_digest_algorithm,
                    )

                    self._send(message)

                    return False

                validation2 = crypto_funcs.validate_cc_chain(
                    cert, self.intermediate_certs, self.roots, self.chain
                )

                logger.warning(f"Validation2: {validation2}")

                if not validation2:
                    rep = {"type": "CHALLENGE_AUTH_REP", "status": "FAILED"}

                    message = crypto_funcs.create_secure_message(
                        rep,
                        self.shared_key,
                        self.used_symetric_cipher,
                        self.used_cipher_mode,
                        self.used_digest_algorithm,
                    )

                    self._send(message)

                    return False

                logger.info("ACCEPTING VALIDATION")

                rep = {"type": "CHALLENGE_AUTH_REP", "status": "SUCCESS"}

                message = crypto_funcs.create_secure_message(
                    rep,
                    self.shared_key,
                    self.used_symetric_cipher,
                    self.used_cipher_mode,
                    self.used_digest_algorithm,
                )

                self._send(message)

                return True

            rep = {"type": "CHALLENGE_AUTH_REP", "status": "FAILED"}

            message = crypto_funcs.create_secure_message(
                rep,
                self.shared_key,
                self.used_symetric_cipher,
                self.used_cipher_mode,
                self.used_digest_algorithm,
            )

            self._send(message)

            return False

    def process_auth_server(self, message):
        """
		Function used to process a Server Authentication Challenge put forward by the Client
        :param message: The message that came from the client (used to get the client's nonce)
		:return True: Authentication response built and sent
		"""
        self.server_cert = crypto_funcs.load_certificate(
            "server_certs/secure_server.pem"
        )
        self.server_ca_cert = crypto_funcs.load_certificate(
            "server_roots/Secure_Server_CA.pem"
        )
        self.rsa_public_key = self.server_cert.public_key()
        self.rsa_private_key = crypto_funcs.load_private_from_pem(
            "server_certs/server_key.pem"
        )

        nonce = message["nonce"]
        signature = crypto_funcs.rsa_signing(
            base64.b64decode(nonce), self.rsa_private_key
        )

        message = {
            "type": "AUTH_SERVER_REP",
            "signature": base64.b64encode(signature).decode(),
            "server_cert": crypto_funcs.get_certificate_bytes(
                self.server_cert
            ).decode(),
            "server_root": crypto_funcs.get_certificate_bytes(
                self.server_ca_cert
            ).decode(),
        }

        sec_message = crypto_funcs.create_secure_message(
            message,
            self.shared_key,
            self.used_symetric_cipher,
            self.used_cipher_mode,
            self.used_digest_algorithm,
        )

        self._send(sec_message)
        return True

    def validate_login(self, username, answer):
        """
		Used to validate whether the challenge was correctly answered
		:param username: The username that came from the client
        :param answer: The answer to the challenge that came from the client
		:return True: Login was successful
        :return False: Login was not successful
        """
        with open("credentials_db/users.csv") as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=";")

            line_count = 0
            user_password = None
            user_permissions = None
            for row in csv_reader:
                logger.debug(
                    "EMAIL: "
                    + row[0]
                    + " RECEIVED: "
                    + username
                    + " EQUALITY: "
                    + str(row[0] == username)
                )
                if line_count == 0:  # Ignore header row
                    line_count += 1
                    continue

                else:
                    if row[0] == username:  # We found our username
                        user_password = row[1]
                        user_permissions = row[3]
                        break

                line_count += 1

            if user_password is not None:  # If we found our user
                correct_answer = (str(self.nonce) + user_password).encode("utf-8")

                public_pem = crypto_funcs.load_public_from_pem(self.client_public_pem)

                if not crypto_funcs.validate_rsa_signature(
                    answer, correct_answer, public_pem
                ):
                    rep = {"type": "CHALLENGE_AUTH_REP", "status": "FAILED"}

                    message = crypto_funcs.create_secure_message(
                        rep,
                        self.shared_key,
                        self.used_symetric_cipher,
                        self.used_cipher_mode,
                        self.used_digest_algorithm,
                    )

                    self._send(message)

                    return False

                if user_permissions != "t":

                    rep = {"type": "CHALLENGE_AUTH_REP", "status": "DENIED"}

                    message = crypto_funcs.create_secure_message(
                        rep,
                        self.shared_key,
                        self.used_symetric_cipher,
                        self.used_cipher_mode,
                        self.used_digest_algorithm,
                    )

                    self._send(message)

                    return False

                return True

            rep = {"type": "CHALLENGE_AUTH_REP", "status": "FAILED"}

            message = crypto_funcs.create_secure_message(
                rep,
                self.shared_key,
                self.used_symetric_cipher,
                self.used_cipher_mode,
                self.used_digest_algorithm,
            )

            self._send(message)

            return False

    def process_negotiation(self, message: str):
        """
		Processes a NEGOTIATION_REQ message from the client.
        This message will trigger the negotiation process where the server will chose the algorithms to be used.
        If there is not match in the algorithms supported by the client and the ones supported by the client the
        communication will be closed.
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug(f"Process Negotation: {message}")

        symetric_ciphers = message["algorithms"]["symetric_ciphers"]
        chiper_modes = message["algorithms"]["chiper_modes"]
        digest_algorithms = message["algorithms"]["digest_algorithms"]

        for sm_cipher in symetric_ciphers:
            if sm_cipher in self.symetric_ciphers:
                self.used_symetric_cipher = sm_cipher
                break

        for cipher_md in chiper_modes:
            if cipher_md in self.cipher_modes:
                self.used_cipher_mode = cipher_md
                break

        for digest_alg in digest_algorithms:
            if digest_alg in self.digest_algorithms:
                self.used_digest_algorithm = digest_alg
                break

        message = {
            "type": "NEGOTIATION_REP",
            "algorithms": {
                "symetric_cipher": self.used_symetric_cipher,
                "cipher_mode": self.used_cipher_mode,
                "digest_algorithm": self.used_digest_algorithm,
            },
        }

        if (
            self.used_symetric_cipher is not None
            and self.used_cipher_mode is not None
            and self.used_digest_algorithm is not None
        ):
            self._send(message)
            return True

        return False

    def process_dh_init(self, message: str):
        """
		Processes a DH_INIT message from the client.
        This message will trigger the exchange of public key and generation of the shared key.
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        self.p = message["parameters"]["p"]
        self.g = message["parameters"]["g"]
        public_key_pem_client = bytes(message["parameters"]["public_key"], "ISO-8859-1")

        try:
            self.private_key, self.public_key_pem = crypto_funcs.diffie_hellman_server(
                self.p, self.g, public_key_pem_client
            )

            message = {
                "type": "DH_SERVER_KEY",
                "key": str(self.public_key_pem, "ISO-8859-1"),
            }

            self._send(message)

            self.shared_key = crypto_funcs.generate_shared_key(
                self.private_key, public_key_pem_client, self.used_digest_algorithm
            )

            return True
        except:
            return False

    def process_open(self, message: str) -> bool:
        """
		Processes an OPEN message from the client.
		This message should contain the filename.
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.info("Process Open: {}".format(message))
        if self.state != STATE_CLIENT_AUTH:
            logger.warning("Invalid state. Discarding")
            return False

        if not "file_name" in message:
            logger.warning("No filename in Open")
            return False

        # Only chars and letters in the filename
        file_name = re.sub(r"[^\w\.]", "", message["file_name"])
        file_path = os.path.join(self.storage_dir, file_name)
        if not os.path.exists("files"):
            try:
                os.mkdir("files")
            except:
                logger.exception("Unable to create storage directory")
                return False

        try:
            self.file = open(file_path, "wb")
            logger.info("File open")
        except:
            logger.exception("Unable to open file")
            return False

        self._send({"type": "OK"})

        self.file_name = file_name
        self.file_path = file_path
        self.state = STATE_OPEN
        return True

    def process_data(self, message: str) -> bool:
        """
		Processes a DATA message from the client.
		This message should contain a chunk of the file.
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Data: {}".format(message))
        if self.state == STATE_OPEN or self.state == STATE_KEY_ROTATION:
            self.state = STATE_DATA

        elif self.state == STATE_DATA:
            # Next packets
            pass

        else:
            logger.warning("Invalid state. Discarding")
            return False

        try:
            data = message.get("data", None)
            if data is None:
                logger.debug("Invalid message. No data found")
                return False

            bdata = base64.b64decode(message["data"])

        except:
            logger.exception("Could not decode base64 content from message.data")
            return False

        try:
            self.file.write(bdata)
            self.file.flush()
        except:
            logger.exception("Could not write to file")
            return False

        return True

    def process_close(self, message: str) -> bool:
        """
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session.
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Close: {}".format(message))

        self.transport.close()
        if self.file is not None:
            self.file.close()
            self.file = None

        self.state = STATE_CLOSE

        return True

    def _send(self, message: str) -> None:
        """
		Effectively encodes and sends a message.

		:param message: The message to send
		:return:
		"""
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + "\r\n").encode()
        self.transport.write(message_b)


def main():
    global storage_dir

    parser = argparse.ArgumentParser(description="Receives files from clients.")
    parser.add_argument(
        "-v",
        action="count",
        dest="verbose",
        help="Shows debug messages (default=False)",
        default=0,
    )
    parser.add_argument(
        "-p",
        type=int,
        nargs=1,
        dest="port",
        default=5000,
        help="TCP Port to use (default=5000)",
    )

    parser.add_argument(
        "-d",
        type=str,
        required=False,
        dest="storage_dir",
        default="files",
        help="Where to store files (default=./files)",
    )

    args = parser.parse_args()
    storage_dir = os.path.abspath(args.storage_dir)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    if port <= 0 or port > 65535:
        logger.error("Invalid port")
        return

    if port < 1024 and not os.geteuid() == 0:
        logger.error("Ports below 1024 require eUID=0 (root)")
        return

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
    tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == "__main__":
    main()
