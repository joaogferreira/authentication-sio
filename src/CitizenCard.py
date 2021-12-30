import base64, os, datetime, PyKCS11, pem
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

class CitizenCard:

    def __init__(self):
        lib ='/usr/local/lib/libpteidpkcs11.so'
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        
        slots = self.pkcs11.getSlotList()
        self.slot = slots[0]
        self.session = self.pkcs11.openSession(self.slot)

    def digital_signature(self, text):
        cit_auth_priv_key = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),])[0]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS,None)
        return bytes(self.session.sign(cit_auth_priv_key, text, mechanism))

    def get_public_key(self, transformation = lambda key: serialization.load_der_public_key(bytes(key.to_dict()['CKA_VALUE']), backend=backend)):
        return transformation(self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0])
        
    def get_private_key(self):
        return self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

    def load_certificate_authentication(self):
        obj = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
        all_attr = [PyKCS11.CKA_VALUE]
        attr = self.session.getAttributeValue(obj, all_attr)[0]
        cert = x509.load_der_x509_certificate(bytes(attr), default_backend())
        return cert

    def load_name(self):
        cert = self.load_certificate_authentication()
        return cert.subject.get_attr_for_oid(NameOID.COMMON_NAME)[0].value
