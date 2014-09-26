import os
import time

from tls.hello_message import ClientHello, ProtocolVersion, Random, parse_server_hello

# Anonymous handshake
 ClientHello(
    client_version=ProtocolVersion(major=3, minor=0),
    random=Random(gmt_unix_time=time.time(), random_bytes=os.urandom(24)),
    session_id='',
    # TODO: cipher suites should be enums
    cipher_suites=[b'\x00\x6B'],
    compression_methods=[0],
    extensions=[]
)


class _TestHandShakeProtocol(Protocol):
    def __init__(self, self):
        self.buffer = []

    def dataReceived(self, data):
        self.buffer.append(data)
        try:
            parse_handshake_messages
        except:
            pass


class TestClientHandshakes(object):
    def test_anonymous_handshake(self):
        client = ClientTLS('localhost', ...)
        client.proto = _TestHandShakeProtocol
        session = client.start()
        assert isinstance(session, Session)
        session.finish()
