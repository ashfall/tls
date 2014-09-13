from pdb import set_trace as st

from tls.hello_message import (
    ClientHello, ServerHello,
    parse_client_hello, parse_server_hello
)

"""
1. Send ClientHello
2. Send ServerHello
"""

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
    # Successfully parsed Client Hello

    server_hello_bytes= (
        b'\x03\x00'
        b'\x05\x06\x07\x08'
        b'9876543210987654321087654321'
    )
    if client_hello.session_id == '':
        # generate a new session id
        s_id = b'001'
        server_hello_bytes += chr(len(s_id))
        server_hello_bytes += s_id

    server_hello_bytes += client_hello.cipher_suites[0]     # Just pick one for now.
    # We don't compress things here.
    server_hello_bytes += '\x00'

    # No extensions.
    server_hello_bytes += '\x00\x00'

    server_hello = parse_server_hello(server_hello_bytes)
    assert isinstance(server_hello, ServerHello)







if __name__ == '__main__':
    test_start_handshake()
