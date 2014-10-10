from __future__ import absolute_import, division, print_function

import os

from tls.hello_message import ClientHello, ProtocolVersion

from tls.message import Handshake, HandshakeType

from tls.record import TLSPlaintext, ContentType


class ClientTLS(object):
    """
    The user will create this and pass to it the things needed to create a
    ClientHello object.
    """

    def __init__(self, major_version, minor_version, gmt_unix_time, session_id='', cipher_suites, compression_methods, extensions=''):
        self.major_version = major_version
        self.minor_version = minor_version
        self.gmt_unix_time = gmt_unix_time      # TODO:Figure out how togenerate this
        self.random_bytes = os.urandom(28)
        self.session_id = session_id            # TODO: How to we generate a session ID?
        self.cipher_suites = cipher_suites
        self.compression_methods = compression_methods
        self.extensions = extensions


    def start(self, write_to_wire_callback, wire_close_callback, verify_callback=None):
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

        # Create a Connection object and pass the ClientHello-Handshake struct to it.
        conn = Connection(self, write_to_wire_callback)
        conn.handshake_msg_store[handshake.msg_type] = handshake
        return conn

    def send_reply(self, last_handshake_msg_type, handshake_msg_store, write_to_wire_callback):
        if last_handshake_msg_type == HandshakeType.SERVER_HELLO_DONE:
            # Send Certificate*
            # Send ClientKeyExchange*
            # Send CertificateVerify*
            # [ChangeCipherSpec]
            # Send Finished

        elif last_handshake_msg_type == HandshakeType.FINISHED:
            # Go to APP_DATA state



class ServerTLS(object):
    """
    The user will create this and pass to it the things needed to create a
    ServerHello object.
    """
    def __init__(self, major_version, minor_version, gmt_unix_time, session_id='', cipher_suites, compression_methods, extensions='')):
        self.major_version = major_version
        self.minor_version = minor_version
        self.gmt_unix_time = gmt_unix_time      # TODO:Figure out how togenerate this
        self.random_bytes = os.urandom(28)
        self.session_id = session_id            # We don't support session resumption yet.

    def start(self, write_to_wire_callback, verify_callback=None):
        conn = Connection(write_to_wire_callback)
        return conn

    def send_reply(self, last_handshake_msg_type, handshake_msg_store, write_to_wire_callback):
        if last_handshake_msg_type == HandshakeType.CLIENT_HELLO:
            # Send ServerHello
            client_hello = handshake_msg_store[HandshakeType.CLIENT_HELLO]
            server_hello = ServerHello(
                server_version=ProtocolVersion(
                    major=self.major_version,
                    minor=self.minor_version
                ),
                random=Random(
                    gmt_unix_time=self.gmt_unix_time,
                    random_bytes=self.random_bytes
                ),
                session_id=self.session_id,
                cipher_suite=self.cipher_suite,                    # TODO: This needs to be picked from ClientHello.cipher_suites
                compression_methods=CompressionMethod.NULL,        # We don't support Compression
                extensions=self.extensions,
            )
            server_hello_as_bytes = server_hello.as_bytes()
            handshake = Handshake(
                msg_type=HandshakeType.SERVER_HELLO,
                length=len(server_hello_as_bytes),
                body=server_hello
            )
            tls_plaintext_record = TLSPlaintext(
                type=ContentType.HANDSHAKE,
                version=ProtocolVersion(
                    major=self.major_version,
                    minor=self.minor_version
                ),
                fragment=handshake.as_bytes()   # TODO: Implement fragmentation mechanism here.
            )
            write_to_wire_callback(tls_plaintext_record.as_bytes())
            handshake_msg_store[HandshakeType.SERVER_HELLO] = handshake


            # Send Certificate*
            # Send ServerKeyExchange*
            # Send CertificateRequest*


            # Send ServerHelloDone
            server_hello_done = ServerHelloDone()
            handshake = Handshake(
                msg_type=Handshake.SERVER_HELLO_DONE,
                length=len(server_hello_done.as_bytes()),
                body=server_hello_done
            )
            tls_plaintext_record = TLSPlaintext(
                type=ContentType.HANDSHAKE,
                version=ProtocolVersion(
                    major=self.major_version,
                    minor=self.minor_version
                ),
                fragment=handshake.as_bytes()
            )
            handshake_msg_store[HandshakeType.SERVER_HELLO_DONE] = handshake


        elif last_handshake_msg_type == HandshakeType.FINISHED:
            # Send [ChangeCipherSpec]
            # Send Finished
            # Go to APP_DATA state



class Connection(object):

    def __init__(self, xTLS, write_to_wire_callback):
        self.write_to_wire_callback = write_to_wire_callback
        self.xTLS = xTLS
        self.handshake_msg_store = {}

    def structure_bytes_from_wire(self, input_bytes):
        """
        Receive data and build a structure out of it.
        """
        # TODO: Buffering of fragmented messages goes here.

        tls_plaintext_record = parse_tls_plaintext(input_bytes)
        if tls_plaintext_record.type == ContentType.HANDSHAKE:
            handshake_struct = parse_handshake_struct(tls_plaintext_record.fragment)
            self.handshake_msg_store[handshake_struct.msg_type] = handshake_struct
            self.xTLS.send_reply(handshake_struct.msg_type, self.handshake_msg_store, self.write_to_wire_callback)


    def construct_bytes_from_application_and_write_to_wire(self, output):
        """
        Encrypt application data and send. This is only useful in APP_DATA state.
        """
        encrypted_output = encrypt_output_bytes_with_negotiated_cipher_suite
        self.write_to_wire_callback(encrypted_output)
