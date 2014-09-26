import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from tls.hello_message import (
    ClientHello, ServerHello, parse_client_hello, parse_server_hello
)

from pdb import set_trace as ST

"""
1. Send ClientHello
2. Send ServerHello
# TODO: Send Certificate
3. Send ServerHelloDone
4. Send ClientKeyExchange

XXX: Send the rsa public key in a message.
TODO: Next, parse an EncryptedPreMasterSecret message with the RSA-encrypted data.
"""

class ServerHelloDone(object):
    """
    Just to represent a ServerHelloDone object.
    """


def _get_EncryptedPreMasterSecret_struct(pre_master_secret):
    """
    This is what is resonsible for creating the PreMasterSecret struct.
    """


def _get_ClientKeyExchange_message(KeyExchangeAlgorithm, client_version_bytes):
    if KeyExchangeAlgorithm == 'rsa':
         r = os.urandom(46)
        packet = client_version_bytes + r
        pre_master_secret = parse_pre_master_secret(packet)
        exchange_keys = _get_EncryptedPreMasterSecret_struct(pre_master_secret)
    elif KeyExchangeAlgorithm in ['dhe_dss', 'dhe_rsa', 'dh_dss', 'dh_rsa', 'dh_anon']:
        exchange_keys = _get_ClientDiffieHellmanPublic_struct()
    # No error handling because YOLO

    # TODO: Pass exchange_keys to something that parses a ClientKeyExchange struct.


def test_start_handshaking():
    client_hello_bytes = (
        b'\x03\x00'
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x00'  # session_id.length
        b''  # session_id.session_id
        b'\x00\x02'  # cipher_suites length
        b'\x00\x6B'  # cipher_suites
        b'\x01'  # compression_methods length
        b'\x00'  # compression_methods
        b'\x00\x00'  # extensions.length
        b''  # extensions.extension_type
        b''  # extensions.extensions
    )
    st()
    client_hello = parse_client_hello(client_hello_bytes)
    assert isinstance(client_hello, ClientHello)
    print "ClientHello sent"

    server_hello_bytes = (
        b'\x03\x00'
        b'\x05\x06\x07\x08'
        b'9876543210987654321087654321'
    )
    if client_hello.session_id == '':
        # generate a new session id
        s_id = b'001'
        server_hello_bytes += chr(len(s_id))
        server_hello_bytes += s_id

    # Just pick one for now.
    server_hello_bytes += client_hello.cipher_suites[0]
    # We don't compress things here.
    server_hello_bytes += '\x00'
    # No extensions.
    server_hello_bytes += '\x00\x00'
    server_hello = parse_server_hello(server_hello_bytes)
    assert isinstance(server_hello, ServerHello)
    print "Successfully generated ServerHello after receiveing the ClientHello message."

    # Generate server's RSA key that the client can use.
    server_rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    server_rsa_public_key = private_key.public_key()

    # Don't really need to write it this way, sorry about the extra object
    server_hello_done = ServerHelloDone()
    assert isinstance(server_hello_done, ServerHelloDone)
    print "ServerHelloDone."

    # Let's try to create a ClientKeyExchange object.
    # 1. generate a 48-byte PreMasterSecret message.
    # 2. Encrypt it using server_rsa_public_key
    # 3. Parse the result in an encrypted premaster secret message.

    r = os.urandom(46)
    pre_master_secret_bytes = b'\x03\x00' + r
    encrypted_pre_master_secret = server_rsa_public_key.encrypt(
        pre_master_secret,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


