
import numpy as np
import binascii
import logging
import asyncio
import time
import math
import sys
import subprocess
import hashlib
import os
sys.path.insert(1,'~/.playground/connectors/crap/')
from itertools import chain
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT32, BUFFER, LIST, STRING
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport

from playground.network.packet import PacketType, FIELD_NOT_SET


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime,os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from os.path import exists, join
logger = logging.getLogger("playground.__connector__." + __name__)

CERT_DIR = "/home/student_20194/soap/certs/"
KEY_F = str(CERT_DIR+"ns.key")
CSR_F = str(CERT_DIR+"csr.pem")
CERT_F = str(CERT_DIR+"ns.crt")
SIGNED_CERT_F = str(CERT_DIR+"csr.pem_signed.cert")
SIGNING_KEY_F = str(CERT_DIR+"key.pem")
class CrapPacketType(PacketType):
   DEFINITION_IDENTIFIER = "crap"
   DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
   DEFINITION_IDENTIFIER = "crap.handshakepacket"
   DEFINITION_VERSION = "1.0"
   NOT_STARTED = 0
   SUCCESS     = 1
   ERROR       = 2
   FIELDS = [
       ("status", UINT8),
       ("nonce", UINT32({Optional:True})),
       ("nonceSignature", BUFFER({Optional:True})),
       ("signature", BUFFER({Optional:True})),
       ("pk", BUFFER({Optional:True})),
       ("cert", BUFFER({Optional:True})),
       ("certChain", LIST(BUFFER, {Optional:True}))
   ]

class DataPacket(CrapPacketType):
   DEFINITION_IDENTIFIER = "crap.datapacket"
   DEFINITION_VERSION = "1.0"
   FIELDS = [
        ("data", BUFFER)
    ]
class ErrorPacket(CrapPacketType):
        DEFINITION_IDENTIFIER = "crap.errorpacket"
        DEFINITION_VERSION = "1.0"
        FIELDS = [
           ("message", STRING)
        ]

################################
# Utility functions
################################

def generateCSR(key):
    	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, u"China"),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tianjin"),
		x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jinnan"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Soap"),
		x509.NameAttribute(NameOID.COMMON_NAME, u"20191.10.20.30"),
	])).sign(key, hashes.SHA256(), default_backend())


	with open(CSR_F, "wb") as cf:
		cf.write(csr.public_bytes(serialization.Encoding.PEM))

def getCertFromCSR(key):
	if not os.path.exists(CERT_F):
		bashCommand = str("openssl x509 -req -in "+CSR_F+" -CA " +SIGNED_CERT_F+ " -CAkey "+SIGNING_KEY_F+ " -CAcreateserial -out "+CERT_F)
		output = subprocess.check_output(['bash','-c', bashCommand])
	return getCertFromFile(CERT_F)

def createPacket(packet, *args, **kwargs):
    return packet(*args, **kwargs)

def serializeKey(key):
    return key.public_bytes(encoding=Encoding.PEM,format=PublicFormat.SubjectPublicKeyInfo)

def deserializeKey(key):
    return load_pem_public_key(key,backend=default_backend())    

def getCertFromFile(CERT_F):
	print("Getting certificate signed by root")
	with open(CERT_F, "rb") as CERT_F:
		print(CERT_F)
		cert_bytes = CERT_F.read()
	# print("Got cert bytes?")
	cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
	# print("Got cert")
	return cert

def getKeyFromCert(cert):
	return cert.public_key()

def serializeCert(cert):
	return cert.public_bytes(serialization.Encoding.PEM)

def deserializeCert(certBytes):
	return x509.load_pem_x509_certificate(certBytes, default_backend())

def mySign(to_sign,key):
	print(key)
	return (key).sign(
            to_sign, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),hashes.SHA256()
        )
def create_self_signed_cert(key):
    	print(key)
	if os.path.exists(CERT_F):
		print("Certificate file exists, loading..")
		with open(CERT_F, "rb") as CERT_F:
			cert_bytes = CERT_F.read()
			cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
	else:
		print("Generating certificate")
		target = issuer = x509.Name([
			x509.NameAttribute(NameOID.COMMON_NAME, u"20191.9.100.200")
        ])
		cert = x509.CertificateBuilder().subject_name(
        	target
        ).issuer_name(
        	issuer
        ).public_key(
        	key.public_key()
        ).serial_number(
        	x509.random_serial_number()
        ).not_valid_before(
        	datetime.datetime.utcnow()
        ).not_valid_after(
        	datetime.datetime.utcnow() + datetime.timedelta(days=100)
        ).add_extension(
        	x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        	critical=False,
        ).sign(key, hashes.SHA256(), default_backend())


		with open(CERT_F, "wb") as cf:
			cf.write(cert.public_bytes(serialization.Encoding.PEM))
		return cert

def generatekey():
    if os.path.exists(KEY_F):
        print("Key file exists, loading..")
        with open(KEY_F, "rb") as KEY_F:
          private_key = serialization.load_pem_private_key(KEY_F.read(), password=b'mypassword',backend=default_backend())
    else:
        print("Generating Key Please standby")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem_p = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        )
        print("key generating")
        with open(KEY_F, "wb") as kf:
            kf.write(pem_p)
    print("key generated")
    return private_key





################################
# Transport Definition
################################


class CrapTransport(StackingTransport):
    def __init__(self, key, mode=1, *args, **kwargs):
        self.key = key
        self.closed = False
        self.called_close = False
        hash1 = hashlib.sha256(key).digest()
        hash2 = hashlib.sha256(hash1).digest()
        hash3 = hashlib.sha256(hash2).digest()
        if mode == 1: # Client
	        self.iv = hash1[:12]
	        self.iv_other = hash1[12:24]
        else: 
	        self.iv_other = hash1[:12]
	        self.iv = hash1[12:24]
        if mode==1:
        	self.encKey = hash2[:16]
	        self.decKey = hash3[:16]
	        self.aesgcmEncrypt = AESGCM(self.encKey)
	        self.aesgcmDecrypt = AESGCM(self.decKey)
        else:
            self.decKey = hash2[:16]
            self.encKey = hash3[:16]
            self.aesgcmEncrypt = AESGCM(self.encKey)
            self.aesgcmDecrypt = AESGCM(self.decKey)
        super().__init__(*args, **kwargs)
        
    def close(self):
        print("crap: called close")
        # print("CALLED CLOSE at ", self.seq)
        if self.called_close or self.closed:
            return
        self.called_close = True
        self.closed = True
        self.lowerTransport().close()

    def write(self, data):
        print("crap write called",self.closed or self.called_close)
        if self.closed or self.called_close:
            return
        aesgcm_notedown = AESGCM(self.encKey)
        encrypted_data = aesgcm_notedown.encrypt(nonce=self.iv, data=data, associated_data =None)
        length = len(self.iv)
        temp = int.from_bytes(self.iv, "big") + 1
        self.iv = temp.to_bytes(length, 'big')
        datapacket = createPacket(DataPacket, data=encrypted_data)
        self.lowerTransport().write(datapacket.__serialize__())

    def other_closed(self):
        self.closed = True
        self.lowerTransport().close()

    def received(self, seq):
        self.stop_qs[seq].put('stop')
        self.acks.add(seq)


################################
# Protocol Definition
################################


class CrapProtocol(StackingProtocol):
    def __init__(self, mode, timeout=3):
        super().__init__()
        self.mode = mode
        self.handshake = Handshaker()
        self.buffer = CrapPacketType.Deserializer()
        self.last_received = None
        self.received_data = {}


    def connection_made(self, transport):
        print(self.mode,"Crap connection_made")
        self.transport = transport
        if self.mode == "client":
            to_send = self.handshake.initialize()
            self.transport.write(to_send.__serialize__())

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        self.buffer.update(data)
        for packet in self.buffer.nextPackets():
            print("here")
            print(self.mode,"handsahek completete?",self.handshake.complete,"packet",packet)
            if isinstance(packet,ErrorPacket):
            	print("Error packet:",packet.message)
            if not self.handshake.complete and isinstance(packet, HandshakePacket):
                print(self.mode, "crap received handshakepacket")
                self.process_handshake(packet)

            elif self.handshake.complete and  isinstance(packet, DataPacket):
                print(self.mode, 'crap got data packet')
                aesgcm = AESGCM(self.higherProtocol().transport.decKey)
                print("Decrypting iv:",self.higherProtocol().transport.iv_other)
                print("Decrytping key:",self.higherProtocol().transport.decKey)


                try:
                    print("Try decrypt")
                    aesgcm = AESGCM(self.higherProtocol().transport.decKey)
                    data = aesgcm.decrypt(nonce=self.higherProtocol().transport.iv_other, data=packet.data, associated_data=None)
                except Exception as e:
	                print("Exception decrypt")
	                aesgcm = AESGCM(self.higherProtocol().transport.encKey)
	                data = aesgcm.decrypt(nonce=self.higherProtocol().transport.iv, data=packet.data, associated_data=None)
                print(int.from_bytes(self.higherProtocol().transport.iv_other, "big"))
                l = len(self.higherProtocol().transport.iv_other)
                temp = int.from_bytes(self.higherProtocol().transport.iv_other, "big") + 1
                temp = temp.to_bytes(l, 'big')
                self.higherProtocol().transport.iv_other = temp[:16]
                print("passsint to higer..")
                self.higherProtocol().data_received(data)

            elif self.handshake.complete and isinstance(packet, ShutdownPacket):
                print(self.mode, "crap received shutdownpacket")
                self.process_shutdown_packet(packet)

    def process_handshake(self, packet):
        to_send = self.handshake.process(packet)
        if to_send is not None:
            print(self.mode," to send is not none") 
            self.transport.write(to_send.__serialize__())

           
        if self.handshake.complete:
        	if self.mode=="client":
        		print(self.mode,"---------- creating transport and calling connection made")
        		self.higherProtocol().connection_made(
	                CrapTransport(
	                    lowerTransport=self.transport,mode=1,key=self.handshake.shared_key
	                ))
	        else:
	        	print(self.mode," ---------- creating transport and calling connection made")
	        	self.higherProtocol().connection_made(
	                CrapTransport(
	                    lowerTransport=self.transport,mode=2,key=self.handshake.shared_key
	                ))
	        print("connecion made called")

    def process_shutdown_packet(self, packet):
        print(self.mode, 'got shutdownpacket packet')
        self.higherProtocol().transport.data_received(packet)





################################
# Handshaker Definition
################################



class Handshaker(object):
    def __init__(self):
        self.signing_key=generatekey()
        print("key generated")
        csr = generateCSR(self.signing_key)
        print("CSR generated")
        self.cert = getCertFromCSR(self.signing_key)
        self.private_key=ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key=self.private_key.public_key()
        self.root_signed_cert = getCertFromFile(SIGNED_CERT_F)
        self.nonce = np.random.randint(0,2**32)
        self.signature =  mySign(serializeKey(self.public_key),self.signing_key)
        self.shared_key=None
        self.complete = False
        self.received_init = False
        self.shared_secret = False
        self.received_key=None


    def initialize(self):
        serialized_client_public_key = serializeKey(self.public_key)
        serialized_cert_bytes = serializeCert(self.cert)
        self.received_init = True
        print(self.certChain)
       
        # same_shared_key = peer_private_key.exchange(ec.ECDH(), server_private_key.public_key())
        return createPacket(
            HandshakePacket,
            status=HandshakePacket.NOT_STARTED,
            pk = serialized_client_public_key,
            cert = serialized_cert_bytes,
            signature = self.signature,
            nonce = self.nonce,
            certChain = self.certChain
        )

    def process(self, packet):
        print("Handshake Process")
        if not self.shared_secret:

            received_public_key = deserializeKey(packet.pk)
            received_cert = deserializeCert(packet.cert)
            received_cert_key = getKeyFromCert(received_cert)
            self.received_key=received_cert_key

        if packet.nonceSignature is not FIELD_NOT_SET:
            # Verify nonce signature
            try:
                # print("Verifying nonce")
                self.received_key.verify(
                    packet.nonceSignature, str(self.nonce).encode(), 
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                # print("Nonce not Verified?")
                # print('There has been an error. Sending error.')
                return createPacket(HandshakePacket, status=HandshakePacket.ERROR)
           
        # Generate nonce signature
        if self.shared_secret:
            # print("crap Server got second packet")
            print("server handshake completed")
            self.complete=True
            return None

   
        # print(packet.pk)
        if packet.signature is not FIELD_NOT_SET:
            try:
                # print("verifying signature")
                self.received_key.verify(
                    packet.signature, packet.pk, 
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                # print("Not Verified?")
                # print('There has been an error. Sending error.')
                return createPacket(HandshakePacket, status=HandshakePacket.ERROR)
               

        for certBytes in packet.certChain:
        	cert = deserializeCert(certBytes)
        	print(received_cert)
        	received_cert_address = received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value
        	cert_address = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value
        	# print("received cert", received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value)
        	# print("chain cert", cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value)
        	if not cert_address.startswith("20194") and not received_cert_address.startswith(cert_address):
        		# print("CA verification failed")
        		return createPacket(HandshakePacket, status=HandshakePacket.ERROR)

  
        nonceSignature =  (self.signing_key).sign(
            str(packet.nonce).encode(), 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),hashes.SHA256()
        )
        self.shared_key = self.private_key.exchange(ec.ECDH(), received_public_key)
        self.shared_secret = True
        if self.received_init:
            self.complete=True
            print("client handshake completed")
            return self.send_success(nonceSignature)
        else:
            # print("crap Server got first packet")
            serialized_cert_bytes=self.cert.public_bytes(serialization.Encoding.PEM)
            serialized_server_public_key = serializeKey(self.public_key)
            return self.send_key(serialized_server_public_key,serialized_cert_bytes, nonceSignature)
            
    def send_success(self,nonceSignature):
        return createPacket(
            HandshakePacket,
            status=HandshakePacket.SUCCESS,
            nonceSignature = nonceSignature     
 )
    def send_key(self, serialized_key,cert_bytes,nonce_signature):
        # print("done3")
        return createPacket(
            HandshakePacket,
            status=HandshakePacket.SUCCESS,
            pk=serialized_key,
            cert=cert_bytes,
            signature=self.signature,
            nonce=self.nonce,
            nonceSignature = nonce_signature,
            certChain = self.certChain
            )
CrapClient=lambda: CrapProtocol(mode="client")
CrapServer=lambda: CrapProtocol(mode="server") 

