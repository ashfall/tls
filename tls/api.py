from __future__ import absolute_import, division, print_function

import os

from tls.hello_message import ClientHello, ProtocolVersion

from tls.message import Handshake, HandshakeType

from tls.record import TLSPlaintext, ContentType


class ClientTLS(object):
    """
    The user wil create this and pass it the things needed to create a
    ClientHello object.
    """

    def __init__(major_version, minor_version, gmt_unix_time, session_id='', cipher_suites, compression_methods, extensions=''):
        self.major_version = major_version
        self.minor_version = minor_version
        self.gmt_unix_time = gmt_unix_time      # TODO:Figure out how togenerate this
        self.random_bytes = os.urandom(28)
        self.session_id = session_id            # TODO: How to we generate a session ID?
        self.cipher_suites = cipher_suites
        self.compression_methods = compression_methods
        self.extensions = extensions


    def start(write_to_wire_callback, wire_close_callback, verify_callback=None):
        """
        First, this creates a ClientHello message and writes it to the wire.
        Then, it creates a Connection object and passes to it the ClientHello
        messsage to extract details of the connection for further use in the
        handshake. Returns that Connection object.
        """
        # Create a ClientHello message.
        client_hello = ClientHello(
            client_version=ProtocolVersion(
                major=self.major_version,
                minor=self.minor_version
            ),
            random=Random(
                gmt_unix_time=self.gmt_unix_time,
                random_bytes=self.random_bytes
            ),
            session_id=self.session_id,
            cipher_suites=self.cipher_suites,
            compression_methods=self.compression_methods,
            extensions=self.extensions,
        )

        client_hello_as_bytes = client_hello.as_bytes()

        # create a handshake struct with this clienthello
        handshake = Handshake(
            msg_type=HandshakeType.CLIENT_HELLO,
            length=len(client_hello_as_bytes),
            body=client_hello
        )

        # Create a TLSPlaintext record for this Handshake struct
        tls_plaintext_record = TLSPlaintext(
            type=ContentType.HANDSHAKE,
            version=ProtocolVersion(
                major=self.major_version,
                minor=self.minor_version
            ),
            fragment=handshake.as_bytes()   # XXX: Implement fragmentation mechanism here.
        )


        # Write this to wire.
        write_to_wire_callback(tls_plaintext_record.as_bytes())

        # Create a Connection object and pass the Client





