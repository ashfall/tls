from pdb import set_trace as st

from tls.hello_message import (
    ClientHello, ServerHello,
    parse_client_hello, parse_server_hello
)

"""
1. Send ClientHello
2. Send ServerHello
3. Send ServerHelloDone
4. Send ClientKeyExchange

TODO: Look at Cryptography to see how the encryption algorithm will work.
"""

class ServerHelloDone(object):
    """
    Just to represent a ServerHelloDone object.
    """



def _get_ClientKeyExchange_message(KeyExchangeAlgorithm):
    if KeyExchangeAlgorithm == 'rsa':
        exchange_keys = _get_EncryptedPreMasterSecret_struct()
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

    # Don't really need to write it this way, sorry about the extra object
    server_hello_done = ServerHelloDone()
    assert isinstance(server_hello_done, ServerHelloDone)
    print "ServerHelloDone."

    # Let's try to create a ClientKeyExchange object.
    # XXX This should probably be factored out somehow.



