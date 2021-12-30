import json, random, asyncio, argparse, coloredlogs, logging, sys, getpass, os, base64, secrets
from CitizenCard import *
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding as padding_assymmetric
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, load_pem_parameters, PublicFormat, load_pem_public_key


logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_PICK_AUTHENTICATION = 2
STATE_AUTHENTICATION_SERVER = 3
STATE_AUTHENTICATION = 4
STATE_CHALLENGE = 5
STATE_SEND_FILE = 6
STATE_DATA = 7
STATE_CLOSE = 8


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.type_auth = None
        self.server_extensions = ['1.3.6.1.5.5.7.3.1']

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        
        message = {'type': 'OPEN', 'file_name': self.file_name}
        self._send(message)

        self.state = STATE_OPEN


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.authentication_request()
                logger.info("Nonce sended")
                self.state = STATE_PICK_AUTHENTICATION

            elif self.state == STATE_PICK_AUTHENTICATION:
                self.conf_authentication(base64.b64decode(message.get('signature', "").encode()),
                                  base64.b64decode(message.get('certificate', "").encode()))
                logger.info("Authentication done.")
                self.state = STATE_AUTHENTICATION_SERVER

            elif self.state == STATE_AUTHENTICATION_SERVER:
                self.pick_authentication_method()
                logger.info("Type Authentication chosen.")
                self.state = STATE_AUTHENTICATION

            elif self.state == STATE_AUTHENTICATION:
                self.challenge(base64.b64decode(message.get('data', "").encode()))
                logger.info("Challenge finished.")
                self.state = STATE_CHALLENGE

            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def authentication_request(self) -> None:
        self.serv_nonce = (secrets.randbits(128)).to_bytes(64, byteorder='big')
        message = {'type': 'PICK_AUTHENTICATION', 'data': None}
        message['data'] = base64.b64encode(self.serv_nonce).decode()
        self._send(message)

    def conf_authentication(self, signature:bytes, cert_bytes:bytes) -> None:

        value = True

        #Load Server Certificate
        server_certificate = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        #Validate Server Certificate
        if not datetime.now() > server_certificate.not_valid_before and datetime.now() < cert_server.not_valid_after:
            value = False

        #Load CA Certificate
        ca = open("CA.crt", "rb")
        ca_certificate = x509.load_pem_x509_certificate(ca.read(), default_backend())

        if server_certificate.issuer != ca_certificate.subject:
            value = False

        try:
            ca_certificate.public_key().verify(
                server_certificate.signature,
                server_certificate.tbs_certificate_bytes,
                padding_assymmetric.PKCS1v15(),
                server_certificate.signature_hash_algorithm,
            )
        except:
            value = False

        try:
            ca_certificate.public_key().verify(
                ca_certificate.signature,
                ca_certificate.tbs_certificate_bytes,
                padding_assymmetric.PKCS1v15(),
                ca_certificate.signature_hash_algorithm,
            )
        except:
            value = False

        #Validate Server Issuer Certificate
        if not datetime.now() > ca_certificate.not_valid_before and datetime.now() < cert_ca.not_valid_after:
            value = False

        try:
            server_certificate.public_key().verify(
                signature,
                self.nonce_to_server,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            value = False

        value = self.check_purpose(server_certificate)
        message = {'type': 'AUTHENTICATION_VALIDATION', 'data': None}
        if not value:
            message['data'] = base64.b64encode(("Error. End of communication.").encode()).decode()
            self._send(message)
            logger.warning("Authentication of the server failed.")
            self.transport.close()
            self.loop.stop()
        else:
            message['data'] = base64.b64encode(("OK").encode()).decode()
            self._send(message)


    def check_purpose(self, cert):
        values = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value

        for v in values:
            if v.dotted_string in self.server_extensions:
                return True
            else:
                return False

    def pick_authentication_method(self) -> None:

        print("Authentication method: ")
        print("1 - Password Authentication")
        print("2 - Citizen card Authentication")
        while self.type_auth == None:
            option = input("Option: ")
            if option == "1":
                self.type_auth = "password"
            elif option == "2":
                self.type_auth = "cc"
            else:
                print("Invalid option\n")

        message = {'type': 'AUTHENTICATION', 'data': None}

        if self.type_auth == "password":
            username = input("Username: ")
            message['data'] = base64.b64encode((self.type_auth + username).encode()).decode()
        else:
            message['data'] = base64.b64encode(self.type_auth.encode()).decode()
        self._send(message)

    def challenge(self, message: str) -> None:
        nonce = message[:64]
        if self.type_auth == "password":
            salt = message[64:]
            data = self.deal_password(nonce, salt)

            message = {'type': 'CHALLENGE', 'data': None}
            message['data'] = base64.b64encode(data).decode()
            self._send(message)
        else:
            cert = self.deal_cc(nonce)
            message = {'type': 'CHALLENGE', 'signature': None, 'certificate': None}
            message['signature'] = str(base64.b64encode(self.signature), "utf-8")
            message['certificate'] = str(base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)), "utf-8")
            self._send(message)


    def deal_password(self, nonce: bytes, salt: bytes) -> bytes:
        password = getpass.getpass()
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(password.encode())
        digest.update(salt)
        
        hash = digest.finalize()
        final_dig = hashes.Hash(hashes.SHA256(), backend=default_backend())
        final_dig.update(nonce)
        final_dig.update(hash)
        
        final_hash = final_dig.finalize()
        return final_hash

    def deal_cc(self, nonce: bytes):
        citizen_card = CitizenCard()
        certificate = citizen_card.load_certificate_authentication()
        self.signature = citizen_card.digital_signature(nonce)
        return certificate

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)


def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()