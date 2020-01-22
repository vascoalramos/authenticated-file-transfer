import sys
import os
import logging
import base64
import json
import requests
import wget
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dsa, utils, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization as crypto_serialization
import PyKCS11

ALGORITHMS = ["3DES", "AES-128"]

logger = logging.getLogger("root")


def generate_key(password, algorithm_name, digest_algorithm=None):
    """
	Function used to generate a Symmetric key given a password and an algorithm
	:param data: A password, the cipher algorithm and digest_algorithm
	:return: The generated Key
	"""
    if digest_algorithm != None:
        # Check which digest algorithm we'll be using
        if digest_algorithm == "SHA256":
            hash_algorithm = hashes.SHA256()
        elif digest_algorithm == "SHA512":
            hash_algorithm = hashes.SHA512()
        elif digest_algorithm == "BLAKE2":
            hash_algorithm = hashes.BLAKE2b(64)
        else:
            raise Exception("Hash Algorithm name not found")
    else:
        hash_algorithm = hashes.SHA256

    password = password.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hash_algorithm,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password)

    # Now we cut the key down to be usable by a certain algorithm by picking random bytes
    if (
        algorithm_name == "AES-128"
    ):  # AES-128 uses a key with 128 bits so we only want the first 16 bytes
        key = key[:16]
    elif (
        algorithm_name == "3DES"
    ):  # 3DES uses a key with 56 bits so we only want the first 8 bytes
        key = key[:8]

    return key


def generate_rsa_key():
    """
	Function used to generate a Private Key
	:return: The generated Private and Public key
	"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (private_key, public_pem)


def generate_digest(message, algorithm):
    """
	Function used to apply a digest function to a given message
	:param message: The message we want to apply a digest to
	:param algorithm: The digestion algorithm
	:return: The digested message
	"""
    hash_algorithm = None

    # Check which digest algorithm we'll be using
    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    digest = hashes.Hash(hash_algorithm, backend=default_backend())

    digest.update(message)
    return digest.finalize()


def generate_mac(message, key, algorithm):
    """
	Function used to apply a digest function to a given message
	:param message: The message we want to apply a MAC to
	:param key: The key to cipher the digestion
	:param algorithm: The digestion algorithm
	:return: The MAC created
	"""
    hash_algorithm = None

    # Check which digest algorithm we'll be using
    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    mac = hmac.HMAC(key, hash_algorithm, backend=default_backend())

    mac.update(message)
    return mac.finalize()


def symmetric_encrypt(message, key, algorithm_name, mode_name):
    """
	Function used to encrypt a message using a symmetric key, a given algorithm and a mode
	:param message: The message we want to encrypt, 
	:param key: A symmetric key
	:param algorithm_name: A cypher algorithm
	:param mode_name: The cypher mode used to cypher
	:return: The cryptogram and an iv, in case we're using CBC
	"""
    cipher = None
    mode = None
    iv = None
    nonce = None
    tag = None

    # Check which mode we'll be using
    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        if algorithm_name == "AES":
            iv = os.urandom(16)
        elif algorithm_name == "3DES":
            iv = os.urandom(8)
        mode = modes.CBC(iv)
    elif mode_name == "GCM":
        iv = os.urandom(12)
        mode = modes.GCM(iv)
    elif mode_name == "None":
        mode = None
    else:
        raise Exception("Mode name not found")

    # Check which algorithm we'll be using
    if algorithm_name == "AES":
        if mode == None:
            raise Exception("No mode was provided for AES")
        key = key[:16]
        block_size = algorithms.AES(key).block_size
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

    elif algorithm_name == "3DES":
        if mode == None or mode_name == "GCM":
            raise Exception("Mode provided isn't supported by 3DES")
        key = key[:8]
        block_size = algorithms.TripleDES(key).block_size
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

    elif algorithm_name == "ChaCha20":
        if mode != None:
            raise Exception("ChaCha20 doesn't support any modes")
        key = key[:32]
        nonce = os.urandom(16)
        block_size = len(message)

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=mode, backend=default_backend()
        )

    else:
        raise Exception("Algorithm name not found")

    encryptor = cipher.encryptor()

    padding = block_size - len(message) % block_size

    if algorithm_name == "AES":
        padding = 16 if padding == 0 else padding
    elif algorithm_name == "3DES":
        padding = 8 if padding == 0 else padding

    if algorithm_name != "ChaCha20":
        message += bytes([padding] * padding)

    cryptogram = encryptor.update(message) + encryptor.finalize()

    if mode_name == "GCM":
        tag = encryptor.tag

    return cryptogram, iv, nonce, tag


def symmetric_key_decrypt(
    cryptogram, key, algorithm_name, mode_name, iv=None, nonce=None, tag=None
):
    """
	Function used to decrypt a cryptogram using a symmetric key and a given algorithm
	:param cryptogram: The cryptogram we want to decrypt
	:param key: A symmetric key
	:param algorithm_name: A cypher algorithm
	:param mode_name: The cypher mode used to cypher
	:param iv: The Initial Vector used
	:param nonce: The Nonce used
	:param tag: The tag used
	:return: The plaintext decrypted message
	"""
    cipher = None
    mode = None

    if mode_name == "ECB":
        mode = modes.ECB()

    elif mode_name == "CBC":
        if iv == None:
            raise Exception("No IV was provided for the CBC mode")

        mode = modes.CBC(iv)

    elif mode_name == "GCM":
        if iv == None:
            raise Exception("No IV was provided for the GCM mode")
        if tag == None:
            raise Exception("No Tag was provided for the GCM mode")

        mode = modes.GCM(iv, tag)

    elif mode_name == "None":
        mode = None

    else:
        raise Exception("Mode name not found")

    if algorithm_name == "AES":
        if mode == None:
            raise Exception("No mode was provided for AES")
        key = key[:16]
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

    elif algorithm_name == "3DES":
        if mode == None or mode_name == "GCM":
            raise Exception("Mode provided isn't supported by 3DES")
        key = key[:8]
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

    elif algorithm_name == "ChaCha20":
        if nonce == None:
            raise Exception("No Nonce was provided for ChaCha20")

        if mode != None:
            raise Exception("ChaCha20 doesn't support any modes")

        key = key[:32]

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=mode, backend=default_backend()
        )

    else:
        raise Exception("Algorithm name not found")

    decryptor = cipher.decryptor()
    ct = decryptor.update(cryptogram) + decryptor.finalize()
    return ct


def diffie_hellman_client():
    """
	Function used to apply the Diffie Hellman algorithm in the client.
	It calculates the parameters and the private and public components
	:return: The shared parameters, the private component and the public component
	"""
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend()
    )

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug(f"My Public Key: {public_key}")
    logger.debug(f"My Public Key in Bytes: {public_key_pem}")

    return p, g, private_key, public_key_pem


def diffie_hellman_server(p, g, public_key_pem):
    """
	Function used to apply the Diffie Hellman algorithm in the server.
	It calculates the private and public components of server.
	:param p: Shared parameter
	:param g: Shared parameter
	:param public_key_pem: Public component of client
	:return: The private component and the public component
	"""
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug(f"My Public Key: {public_key}")
    logger.debug(f"My Public Key in Bytes: {public_key_pem}")

    return private_key, public_key_pem


def generate_shared_key(private_key, public_key_pem, algorithm):
    """
	It generates the shared key of Diffie Hellman.
	:param private_key:
	:param public_key_pem:
	:param algorithm: The digestion algorithm
	"""
    public_key = serialization.load_pem_public_key(
        public_key_pem, backend=default_backend()
    )

    shared_key = private_key.exchange(public_key)

    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    derived_key = HKDF(
        algorithm=hash_algorithm,
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend(),
    ).derive(shared_key)

    logger.info(f"My Shared Key: {derived_key}")
    return derived_key


def create_secure_message(
    message_to_encrypt, shared_key, symetric_cipher, cipher_mode, digest_algorithm
):
    """
	Function used to create a SECURE_X message that encapsulates a given message
	:param message_to_encrypt: The message we want to put in the SECURE_X payload field 
	:param shared_key: The key used in the cypher
	:param symetric_cipher: The cypher algorithm used
	:param cipher_mode: The cypher mode used
	:param digest_algorithm: The digest algorithm used to generate the MAC
	:return: The SECURE_X message
	"""
    message = {
        "type": "SECURE_X",
        "payload": None,
        "mac": None,
        "iv": None,
        "nonce": None,
        "tag": None,
    }

    cryptogram, iv, nonce, tag = symmetric_encrypt(
        str.encode(json.dumps(message_to_encrypt)),
        shared_key,
        symetric_cipher,
        cipher_mode,
    )

    # Encrypt our message
    digest = generate_mac(cryptogram, shared_key, digest_algorithm)

    message["payload"] = base64.b64encode(cryptogram).decode()
    message["mac"] = base64.b64encode(digest).decode()

    if iv != None:
        message["iv"] = base64.b64encode(iv).decode()
    if nonce != None:
        message["nonce"] = base64.b64encode(nonce).decode()
    if tag != None:
        message["tag"] = base64.b64encode(tag).decode()

    return message


def rsa_signing(message, private_key):
    """
	Function used to sign a message with a private key
	:param message: The message to be signed
	:param private_key: The private_key used to sign the message
	:return: The result signature.
	"""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signature


def validate_rsa_signature(signature, message, public_key):
    """
	Function used to verify signature validation
	:param signature: The signrature to be validated
	:param message: The cypher algorithm used
	:param public_key: The cypher mode used
	:return: True if validation successfull, False if not
	"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except:
        logger.error("Signature verification failed")
        return False

    return True


def get_issuer_common_name(cert):
    """
	Function used to retrieve the common name of the issuer of a given certificate.
	:param cert: The certificate.
	:return: If it exists, the common name. Otherwise, None.
	"""
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def get_common_name(cert):
    """
	Function used to retrieve the common name of a given certificate.
	:param cert: The certificate.
	:return: If it exists, the common name. Otherwise, None.
	"""
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def validate_certificate_common_name(cert, issuer):
    """
	Function used to check if the certificate's common name and the issuer's common name are equal.
	:param cert: The certificate.
	:param issuer: The issuer.
	:return: True if are equal. False, otherwise.
	"""
    return get_issuer_common_name(cert) == get_common_name(issuer)


def validate_certificate_signature(cert, issuer):
    """
	Function used to check if the signature of the certificate if correct.
	:param cert: The certificate.
	:param issuer: The issuer.
	:return: True if is verified successfully. False, otherwise.
	"""
    cert_signature = cert.signature
    issuer_public_key = issuer.public_key()

    try:
        issuer_public_key.verify(
            cert_signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except:
        return False

    return True


def load_private_from_pem(filename):
    """
	Function used to load a private key from a given file.
	:param filename: The name of the file that contains the information.
	:return: The private key object.
	"""
    with open(filename, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    return private_key


def load_public_from_pem(pem):
    """
	Function used to load a public key from a given file.
	:param filename: The name of the file that contains the information.
	:return: The public key object.
	"""
    public_key = serialization.load_pem_public_key(pem, backend=default_backend())
    return public_key


def validate_certificate(cert):
    """
	Function used to validate a given certificate.
	:param cert: The ciphertext to decrypt
	:return: True, if the current timestamp is between the limits of validity of the certificate. False, otherwise.
	"""
    today = datetime.now().timestamp()
    return (
        cert.not_valid_before.timestamp() <= today <= cert.not_valid_after.timestamp()
    )


def load_certificate(filename):
    """
	Function used to load a certificate from a given file (tries pem and der).
	:param filename: The name of the file that contains the information.
	:return: The certificate object.
	"""
    try:
        with open(filename, "rb") as pem_file:
            pem_data = pem_file.read()
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return cert
    except:
        logger.warning("Not pem!")

    try:
        with open(filename, "rb") as pem_file:
            pem_data = pem_file.read()
            cert = x509.load_der_x509_certificate(pem_data, default_backend())
        return cert
    except:
        logger.warning("Not der!")


def load_certificate_bytes(cert_bytes):
    """
	Function used to load a certificate in pem from the respective bytes.
	:param cert_bytes: The certificate bytes.
	:return: The certificate object.
	"""
    return x509.load_pem_x509_certificate(cert_bytes, default_backend())


def get_certificate_bytes(cert):
    """
	Fuction used to convert a certificate object to it's respective bytes format.
	:param cert: The certificate to convert.
	:return: The certificate bytes.
	"""
    return cert.public_bytes(crypto_serialization.Encoding.PEM)


def build_chain(chain, cert, intermediate_certs, roots):
    """
	Function used to build the chain of certificates from the base cert all the way to the root.
	"""
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in roots:
        return

    if issuer in intermediate_certs:
        return build_chain(chain, intermediate_certs[issuer], intermediate_certs, roots)

    if issuer in roots:
        return build_chain(chain, roots[issuer], intermediate_certs, roots)

    return


def validate_server_chain(base_cert, root_cert, intermediate_certs, roots, chain):
    """
	Function used to validate a chain of certificates.
	For each certificate, we validate the certificate itself, it's purpose, the common name and if it is revoked.
	:return: True if valid. False, otherwise.
	"""
    roots[root_cert.subject.rfc4514_string()] = root_cert

    build_chain(chain, base_cert, intermediate_certs, roots)

    for idx, cert in enumerate(chain):
        val_cert = validate_certificate(cert)
        if not val_cert:
            return False

        val_puprose = validate_server_purpose(cert, idx)
        if not val_puprose:
            return False

    for i in range(0, len(chain) - 1):
        val_signature = validate_certificate_signature(chain[i], chain[i + 1])
        if not val_signature:
            return False

        val_common_name = validate_certificate_common_name(chain[i], chain[i + 1])
        if not val_common_name:
            return False

        val_revocation = validate_revocation(chain[i], chain[i + 1])
        if val_revocation:
            return False

    return val_cert and val_signature and val_common_name


def load_certificate_crl(filename):
    """
	Function used to load the crl of a certificate from a given file (tries pem and der).
	:param filename: The name of the file that contains the information.
	:return: The crl of the certificate.
	"""
    try:
        with open(filename, "rb") as pem_file:
            pem_data = pem_file.read()
            cert = x509.load_pem_x509_crl(pem_data, default_backend())
        return cert
    except:
        logger.debug("Not pem!")

    try:
        with open(filename, "rb") as pem_file:
            pem_data = pem_file.read()
            cert = x509.load_der_x509_crl(pem_data, default_backend())
        return cert
    except:
        logger.debug("Not der!")
    return cert


def validate_revocation(cert, issuer):
    """
	Function used to check if a given certificate (or it's issuer) is revoked.
	:return: True, if it's revoked. False, otherwise.
	"""
    try:
        builder = ocsp.OCSPRequestBuilder()

        builder = builder.add_certificate(cert, issuer, SHA1())
        req = builder.build()

        for ext in cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value:
            if ext.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                data = req.public_bytes(serialization.Encoding.DER)

                ocsp_url = ext.access_location.value
                request = requests.post(
                    ocsp_url,
                    headers={"Content-Type": "application/ocsp-request"},
                    data=data,
                )

                ocsp_resp = ocsp.load_der_ocsp_response(request.content)
                logger.warning(f"OCSP CERT STATUS: {ocsp_resp.certificate_status}")

                if (
                    ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD
                    or get_common_name(cert) == "ECRaizEstado"
                ):
                    return False
                else:
                    return True
    except:
        logger.debug("OCSP is not available for this certificate!")

    try:
        for ext in cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value:
            for name in ext.full_name:
                file_name = wget.download(name.value)

                revocation_list = load_certificate_crl(file_name)

                if revocation_list is None:
                    return False

                cert_is_revoked = cert.serial_number in [
                    l.serial_number for l in revocation_list
                ]
        try:
            for ext in cert.extensions.get_extension_for_class(x509.FreshestCRL).value:
                for name in ext.full_name:
                    file_name = wget.download(name.value)

                    revocation_list = load_certificate_crl(file_name)

                    if revocation_list is None:
                        return False

                    cert_is_revoked = cert.serial_number in [
                        l.serial_number for l in revocation_list
                    ]
        except:
            logger.debug("DELTA CRL is not available for this certificate!")

        for ext in issuer.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value:
            for name in ext.full_name:
                file_name = wget.download(name.value)

                revocation_list = load_certificate_crl(file_name)

                if revocation_list is None:
                    return False

                isser_is_revoked = issuer.serial_number in [
                    l.serial_number for l in revocation_list
                ]

        try:
            for ext in issuer.extensions.get_extension_for_class(
                x509.FreshestCRL
            ).value:
                for name in ext.full_name:
                    file_name = wget.download(name.value)

                    revocation_list = load_certificate_crl(file_name)

                    if revocation_list is None:
                        return False

                    isser_is_revoked = issuer.serial_number in [
                        l.serial_number for l in revocation_list
                    ]
        except:
            logger.debug("DELTA CRL is not available for this certificate!")

        return cert_is_revoked or isser_is_revoked
    except:
        logger.debug("CRL is not available for this certificate!")

    return True


def validate_server_purpose(cert, indx):
    """
	Function that checks if the given has the right purpose.
	:return: True, if it has. False, otherwise.
	"""
    
    if indx == 0:
        for c in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            if c.dotted_string == "1.3.6.1.5.5.7.3.1":
                return True
        return False
    else:
        return cert.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value.key_cert_sign


def sign_with_cc(message):
    """
	Function used to load the contents of an inserted CC and sign a given message.
	:param message: THe message that is going to be signed.
	:return: The signed message and the CC Certificate in bytes.
	"""
    try:
        lib = "/usr/local/lib/libpteidpkcs11.so"
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        slot = slots[0]
        session = pkcs11.openSession(slot)

        # Get all attributes
        all_attr = list(PyKCS11.CKA.keys())
        all_attr = [e for e in all_attr if isinstance(e, int)]

        # Get the private key
        private_key = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY"),
            ]
        )[0]

        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

        # Sign the message
        signature = bytes(session.sign(private_key, message, mechanism))

        # Get the certificate object from the session
        cert_obj = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"),
            ]
        )[0]

        attr = session.getAttributeValue(cert_obj, all_attr)

        attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

        # Get the x509 certificate using the value from the attribute in the CC
        cert = x509.load_der_x509_certificate(
            bytes(attr["CKA_VALUE"]), default_backend()
        )

        return signature, get_certificate_bytes(cert)
    except:
        logger.error("Error - No card reader / valid CC detected")
        exit(1)


def validate_cc_signature(signature, message, public_key):
    """
	Function used to verify signature validation.
	:param signature: The signature to be validated.
	:param message: The orignal message used to compare.
	:param public_key: The public key of the person/entity that signed the message.
	:return: True if validation successfull, False otherwise.
	"""
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA1())
    except:
        logger.error("Server signature validation failed!")
        return False
    return True


def validate_cc_purpose(cert, indx):
    """
	Function that checks if the given has the right purpose.
	:return: True, if it has. False, otherwise.
	"""

    try:
        if indx == 0:
            for c in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                if c.dotted_string == "1.3.6.1.5.5.7.3.2":
                    return True
            return False
        else:
            return cert.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value.key_cert_sign
    except:
        return False

def validate_cc_chain(base_cert, intermediate_certs, roots, chain):
    """
	Function used to validate a chain of certificates.
	For each certificate, we validate the certificate itself, it's purpose, the common name and if it is revoked.
	:return: True if valid. False, otherwise.
	"""
    path = "root_certificates/"
    folder = os.scandir(path)
    for entry in folder:
        cert = load_certificate(path + "/" + entry.name)
        if cert is not None:
            roots[cert.subject.rfc4514_string()] = cert

    path = "cc_certs/"
    folder = os.scandir(path)
    for entry in folder:
        cert = load_certificate(path + "/" + entry.name)
        if cert is not None:
            intermediate_certs[cert.subject.rfc4514_string()] = cert

    build_chain(chain, base_cert, intermediate_certs, roots)

    for idx, cert in enumerate(chain):
        val_cert = validate_certificate(cert)
        if not val_cert:
            return False

        val_purpose = validate_cc_purpose(cert, idx)
        if not val_purpose:
            return False

    for i in range(0, len(chain) - 1):
        val_signature = validate_certificate_signature(chain[i], chain[i + 1])
        if not val_signature:
            return False

        val_commom_name = validate_certificate_common_name(chain[i], chain[i + 1])
        if not val_commom_name:
            return False

        val_revocation = validate_revocation(chain[i], chain[i + 1])
        if val_revocation:
            return False

    return val_cert and val_signature and val_commom_name

