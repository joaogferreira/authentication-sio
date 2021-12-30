import re, json, asyncio, argparse, coloredlogs, logging, secrets, pem, sys, base64, getpass, os
from aio_tcpserver import tcp_server
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding, hmac
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding as padding_assymmetric
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from datetime import datetime

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

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''
		self.salt_hash = b''

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT


	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
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
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()

		if mtype == 'OPEN':
			ret = self.process_open(message)

		elif mtype == 'PICK_AUTHENTICATION':
			ret = self.nonce_signature(message)
			logger.info('Certificate sended')
			self.state = STATE_PICK_AUTHENTICATION

		elif mtype == 'AUTHENTICATION_VALIDATION':
			ret = self.check_validation(message)
			logger.info("Client validate server")
			self.state = STATE_AUTHENTICATION_SERVER

		elif mtype == 'AUTHENTICATION':
			ret = self.process_authentication(message)
			logger.info("Nonce and salt sended")
			self.state = STATE_AUTHENTICATION

		elif mtype == 'CHALLENGE':
			ret = self.process_challenge(message)
			logger.info("Authentication finished and permissions verified")
			self.state = STATE_CHALLENGE

		elif mtype == 'DATA':
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			ret = self.process_close(message)
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
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
		except Exception:
			logger.exception("Unable to open file")
			return False

		self._send({'type': 'OK'})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True

	def nonce_signature(self, message: str) -> bool:
		logger.debug("Sign nonce: {}".format(message))

		if self.state != STATE_OPEN:
			logger.warning("Invalide state.")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message - no data found")
				return False
			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		nonce = bdata
		file_cert = open("certServer.crt", "rb")
		pem_data = file_cert.read()
		cert = x509.load_pem_x509_certificate(pem_data, default_backend())

		priv_key_server = open("certServer.pem", "rb")
		priv_key = priv_key_server.read()
		priv_key = serialization.load_pem_private_key(
			priv_key,
			password=None,
			backend=default_backend()
		)

		signature = priv_key.sign(
			nonce,
			padding_assymmetric.PSS(
				mgf=padding_assymmetric.MGF1(hashes.SHA256()),
				salt_length=padding_assymmetric.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)

		message = {'type': 'OK', 'certificate': None, 'signature': None}
		message['signature'] = base64.b64encode(signature).decode()
		message['certificate'] = base64.b64encode(cert.public_bytes(Encoding.PEM)).decode()
		self._send(message)

		return True

	def check_validation(self, message: str) -> bool:
		logger.debug("See Validation: {}".format(message))

		if self.state != STATE_PICK_AUTHENTICATION:
			logger.warning("Invalide state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False
			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		if bdata.decode() != "OK":
			logger.warning("Authentication of the server failed. Client will close the connection")
			return False

		self._send({'type': 'OK'})

		return True

	def process_authentication(self, message: str) -> bool:
		logger.debug("Process Authentication: {}".format(message))

		if self.state != STATE_AUTHENTICATION_SERVER:
			logger.warning("Invalide state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False
			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		if "password" in bdata.decode():
			self.type_auth = "password"
			self.client = bdata.decode().split("password")[1]

			if not self.user_verification():
				logger.exception("User does not exist")
				message = {'type': 'ERROR', 'data': "User does not exist"}
				self._send(message)
				return False
		else:
			self.type_auth = "cc"

		self.nonce = (secrets.randbits(128)).to_bytes(64, byteorder='big')
		message = {'type': 'OK', 'data': base64.b64encode(self.nonce + self.salt_hash).decode()}
		self._send(message)

		return True

	def user_verification(self) -> bool:
		file = open("users_db.txt", "r")
		for line in file:
			data = line.split(",")
			if data[0] == self.client:
				self.client_hash = base64.b64decode(data[1].encode())
				self.salt_hash = base64.b64decode(data[2].encode())
				return True
		return False

	def process_challenge(self, message: str) -> bool:
		logger.debug("Process Challenge: {}".format(message))

		if self.state != STATE_AUTHENTICATION:
			logger.warning("Invalide state. Discarding")
			return False

		try:
			data = message.get('data', None)
			signature = message.get('signature', None)
			certificate = message.get('certificate', None)

			if data is None and self.type_auth == "password":
				logger.debug("Invalid message. No data found")
				return False
			elif data is not None and self.type_auth == 'password':
				bdata = base64.b64decode(message['data'])

			if (signature is None or certificate is None) and self.type_auth == "cc":
				logger.debug("Invalid message. No data found")
				return False

		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		if self.type_auth == "password":
			if not self.password(bdata):
				logger.exception("Authentication failed")
				message = {'type': 'ERROR', 'data': "Authentication failed"}
				self._send(message)
				return False
			elif not self.permissions():
				logger.exception("Permission denied")
				message = {'type': 'ERROR', 'data': "Permission denied"}
				self._send(message)
				return False
		else:
			if not self.cc(message):
				logger.exception("Authentication failed")
				message = {'type': 'ERROR', 'data': "Authentication failed"}
				self._send(message)
				return False
			elif not self.check_citizen_card_permissions():
				logger.exception("Permission denied")
				message = {'type': 'ERROR', 'data': "Permission denied"}
				self._send(message)
				return False

		message = {'type': 'OK'}
		self._send(message)
		logger.info("Successfully authenticated")
		self.state = STATE_SEND_FILE
		return True

	def password(self, message: bytes) -> bool:
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(self.nonce)
		digest.update(self.client_hash)
		hash = digest.finalize()
		
		if hash == message:
			return True
		return False

	def permissions(self) -> bool:
		file = open("users_db.txt", "r")
		for line in file:
			data = line.split(",")
			if data[0] == self.client:
				permission = data[3]
				if permission == 'TRUE':
					return True
		return False

	def cc(self, message: str) -> bool:
		cert_cc = base64.b64decode(message['certificate'])
		cert = x509.load_pem_x509_certificate(cert_cc, default_backend())
		self.cert = cert
		verify_cert = self.check_certificate(cert)

		signature = base64.b64decode(message['signature'])
		verify_sign = self.check_signature(signature, cert)

		if not verify_cert or not verify_sign:
			return False
		logger.info('Certificate chain and Signature verified')
		return True

	def check_signature(self, signature, client_cert) -> bool:
		try:
			client_cert.public_key().verify(
				signature,
				self.nonce,
				padding_assymmetric.PKCS1v15(),
				hashes.SHA1()
			)
		except:
			return False

		return True

	def check_certificate(self, cert) -> bool:
		#Purpose - Citizen Card Certificate
		citizen_card_cert = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature
		if citizen_card_cert == False:
			return False

		dic = self.build_dictionaries()
		if dic == False:
			return False

		#Certificate Chain
		chain = self.build_chain(cert)

		#Check if each certificate is used to verify signatures
		for i in range(1, len(chain)):
			purpose = self.check_purpose(chain[i])
			if not purpose:
				return False

		#Check if each certificate is revokated
		crl = self.build_crl()
		for cert in chain:
			if not self.check_crl(cert, crl):
				logger.info("Revoked in crl.")
				return False

		for i in range(0, len(chain)):
			#Verify Validity
			if chain[i].not_valid_after < datetime.now():
				return False
			#Verify Signatures
			if i != len(chain) - 1 and not self.verify_cert_signature(chain[i], chain[i + 1].public_key()):
				return False
			#Verify Root Signature
			if i == len(chain) - 1 and not self.verify_cert_signature(chain[i], chain[i].public_key()):
				return False

		return True

	def build_dictionaries(self) -> bool:
		certs = "PTEID.pem"
		certificates = pem.parse_file(certs)
		self.certs = {}
		self.root = {}

		#PTEID.pem
		for cert in certificates:
			certificate = x509.load_pem_x509_certificate(cert.as_bytes(), default_backend())
			if certificate.not_valid_after > datetime.now():
				self.certs[certificate.subject.rfc4514_string()] = certificate
		
		#Load Root Certificate
		root_cert = "/etc/ssl/certs/Baltimore_CyberTrust_Root.pem"
		with open(root_cert, "rb") as baltimore:
			certificate = x509.load_pem_x509_certificate(baltimore.read(), default_backend())
			self.root[certificate.subject.rfc4514_string()] = certificate
		return True

	def build_chain(self, cert, chain=[]):
		chain.append(cert)

		issuer = cert.issuer.rfc4514_string()
		subject = cert.subject.rfc4514_string()

		if issuer == subject and subject in self.root:
			return chain

		if issuer in self.certs:
			return self.build_chain(self.certs[issuer], chain)
		elif issuer in self.root:
			return self.build_chain(self.root[issuer], chain)

		return chain

	def check_purpose(self, cert) -> bool:
		cert_sign = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign
		return cert_sign

	def build_crl(self):
		crl_folder = "crl/"
		files = [f for f in os.scandir(crl_folder)]
		crl = []
		for f in files:
			with open(f, "rb") as file:
				crlist = x509.load_der_x509_crl(file.read(), default_backend())
				crl.append(crlist)
		return crl

	def check_crl(self, cert, crl) -> bool:
		for revocation_list in crl:
			if revocation_list.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
				return False
		return True

	def verify_cert_signature(self, certificate, public_key_issuer) -> bool:
		try:
			public_key_issuer.verify(
				certificate.signature,
				certificate.tbs_certificate_bytes,
				padding_assymmetric.PKCS1v15(),
				certificate.signature_hash_algorithm,
			)
			return True
		except Exception:
			return False

	def check_citizen_card_permissions(self) -> bool:
		cc_number = self.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
		f = open("users_db.txt", 'r')

		for line in f:
			data = line.split(",")
			possible_number = 'BI' + data[4]
			if cc_number == possible_number:
				if data[3] == 'TRUE':
					return True
		return False

	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_CHALLENGE:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
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
		This message will trigger the termination of this session

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
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)

def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

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


if __name__ == '__main__':
	main()


