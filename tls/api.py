from __future__ import absolute_import, division, print_function

import os
import struct
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tls import prf
from tls.hello_message import ClientHello, ProtocolVersion, Random
from tls.message import (
    ChangeCipherSpec, ClientKeyExchange, Finished, Handshake, HandshakeType,
    parse_handshake_struct
)
from tls.record import ContentType, TLSPlaintext, parse_tls_plaintext


DEFAULT = None


class ClientTLS(object):
    """
    The user will create this and pass to it the things needed to create a
    ClientHello object.
    """

    def __init__(self, server_hostname, cipher_suites, trust_root=DEFAULT,
                 client_certificate_store=None):
        # This corresponds to TLS 1.2
        self.major_version = 3
        self.minor_version = 3
        self.gmt_unix_time = int(time.time())
        self.random_bytes = os.urandom(28)
        self.session_id = b''  # TODO: support sessions. Is empty safe?
        self.cipher_suites = cipher_suites  # This *must* be a list.
        self.compression_methods = [0]  # XXX: this is not intuitive.
        self.extensions = None  # TODO: support this shortly

    def start(self, write_to_wire_callback, wire_close_callback,
              verify_callback=None):
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
        tls_plaintext_record = self._create_handshake_plaintext(handshake)

        # Write this to wire.
        write_to_wire_callback(tls_plaintext_record.as_bytes())

        # Create a Connection object and pass the ClientHello-Handshake
        # struct to it.
        conn = Connection(self, write_to_wire_callback)
        conn.handshake_msg_store[handshake.msg_type] = handshake
        conn.handshake_msg_bytes_list.append(tls_plaintext_record.fragment)
        return conn

    def _create_handshake_plaintext(self, handshake):
        tls_plaintext_record = TLSPlaintext(
            type=ContentType.HANDSHAKE,
            version=ProtocolVersion(
                major=self.major_version,
                minor=self.minor_version
            ),
            # XXX: Implement fragmentation mechanism here.
            fragment=handshake.as_bytes()
        )
        return tls_plaintext_record

    def send_reply(self, last_handshake_msg_type, handshake_msg_store,
                   handshake_msg_bytes_list, write_to_wire_callback):
        if last_handshake_msg_type == HandshakeType.SERVER_HELLO_DONE:
            # Send Certificate*
            # Send ClientKeyExchange*
                # Say server_public_key is obtained from the
                # ServerKeyExchange message somehow.
                # Case RSA:
                r = os.urandom(46)
                pre_master_secret_bytes = struct.pack(
                    '!B', self.major_version
                ) + struct.pack('!B', self.minor_version) + r
                # certs = handshake_msg_store[HandshakeType.Certificate]
                # ok can't parse those right now
                public_numbers = rsa.RSAPublicNumbers(
                    e=65537,
                    n=20744133038750383921455686968193555132016282435071809971939586017872663149639106841321290123990832064907217352698759127148216531428289054962609693255275762023566798483311258773984897126555815064122346924219264002887423866970635514164972960540468169071014398471593867737132970339980107379770274676978982144898321150342777001184597694208591780575700051216744675362937969104464731049660750326048706005317831670570241753658355442703258954194911540834586997295515561813950700028393215028261944476512920543358471138572451115475675404611889688917075458200474503459652480535499607734490352466810023914375502808672653657848771
                )
                server_public_key = public_numbers.public_key(default_backend())
                encrypted_pre_master_secret = server_public_key.encrypt(
                    pre_master_secret_bytes, padding.PKCS1v15()
                )
                client_key_exchange = ClientKeyExchange(
                    exchange_keys=encrypted_pre_master_secret
                )
                handshake = Handshake(
                    msg_type=HandshakeType.CLIENT_KEY_EXCHANGE,
                    length=len(client_key_exchange.as_bytes()),
                    body=client_key_exchange
                )

                tls_plaintext_record = self._create_handshake_plaintext(
                    handshake
                )

                # Write this to wire.
                write_to_wire_callback(tls_plaintext_record.as_bytes())

                # Send CertificateVerify*
                # simplest handshake would now call ChangeCipherSpec...so
                # let's do that.
                ccs_record = TLSPlaintext(
                    type=ContentType.CHANGE_CIPHER_SPEC,
                    version=ProtocolVersion(
                        major=self.major_version,
                        minor=self.minor_version
                    ),
                    # XXX: Implement fragmentation mechanism here.
                    fragment=chr(ChangeCipherSpec.CHANGE_CIPHER_SPEC)
                )

                write_to_wire_callback(ccs_record.as_bytes())

                # now we need to know what PRF from the ciphersuite
                # assuming SHA256 for now

                master_secret = prf(
                    pre_master_secret_bytes,
                    b"master secret",
                    handshake_msg_store[
                        HandshakeType.CLIENT_HELLO
                    ].client_random + handshake_msg_store[
                        HandshakeType.SERVER_HELLO
                    ].server_random,
                    hashes.SHA256(),
                    48
                )

                h = hashes.Hash(hashes.SHA256(), default_backend())
                h.update(b"".join(handshake_msg_bytes_list))
                verify_data = prf(
                    master_secret,
                    b"client finished",
                    h.finalize()
                )
                finished = Finished(verify_data=verify_data)
                handshake = Handshake(
                    msg_type=HandshakeType.FINISHED,
                    length=len(finished.as_bytes()),
                    body=finished
                )
                tls_plaintext_record = self._create_handshake_plaintext(
                    handshake
                )

                write_to_wire_callback(tls_plaintext_record.as_bytes())

        elif last_handshake_msg_type == HandshakeType.FINISHED:
            # Go to APP_DATA state
            pass


class ServerTLS(object):
    """
    The user will create this and pass to it the things needed to create a
    ServerHello object.
    """
    def __init__(self, certificates, dh_params=None):
        self.major_version = 3
        self.minor_version = 3
        self.gmt_unix_time = int(time.time())
        self.random_bytes = os.urandom(28)
        self.session_id = b''  # TODO: support sessions. Is empty safe?
        # eventually these need to be a cert
        self.rsa_private_key = rsa.generate_private_keyt(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def start(self, write_to_wire_callback, verify_callback=None):
        conn = Connection(write_to_wire_callback)
        return conn

    def send_reply(self, last_handshake_msg_type, handshake_msg_store,
                   handshake_msg_bytes_list, write_to_wire_callback):
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
                # TODO: This needs to be picked from ClientHello.cipher_suites
                cipher_suite=self.cipher_suite,
                # We don't support Compression
                compression_methods=CompressionMethod.NULL,
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
                # TODO: Implement fragmentation mechanism here.
                fragment=handshake.as_bytes()
            )
            write_to_wire_callback(tls_plaintext_record.as_bytes())
            handshake_msg_store[HandshakeType.SERVER_HELLO] = handshake

            # Send Certificate*
            # Send ServerKeyExchange*
            #       Sends over self.rsa_public_key somehow.
            server_ecdh_parameters = ServerECDHParams(
                parameters=ECParameters(
                    curve_type=CurveTypes.NAMED_CURVE,
                    namedcurve=NamedCurve.SECT163K1,
                ),
                point=ECPoint(
                    b"\x04" +
                    ecdh_public_key.x.to_bytes("big") +
                    ecdh_public_key.y.to_bytes("big")
                ),
            )
            signer = private_key.signer(
                padding.PKCS1v15(),
                hashes.SHA1(),
            )
            signer.update(client_hello.random)
            signer.update(server_hello.random)
            signer.update(server_ecdh_parameters.as_bytes())
            signature = signer.finalize()
            server_key_exchange = ServerKeyExchange(
                params=server_ecdh_parameters,
                signed_params=signature,
            )
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
            pass


class Connection(object):
    def __init__(self, xtls, write_to_wire_callback):
        self.write_to_wire_callback = write_to_wire_callback
        self.xtls = xtls
        self.handshake_msg_store = {}
        self.handshake_msg_bytes_list = []

    def data_from_wire(self, input):
        """
        Receive data and build a structure out of it.
        """
        # TODO: Buffering of fragmented messages goes here.

        tls_plaintext_record = parse_tls_plaintext(input)
        if tls_plaintext_record.type == ContentType.HANDSHAKE:
            handshake_struct = parse_handshake_struct(
                tls_plaintext_record.fragment
            )
            self.handshake_msg_store[handshake_struct.msg_type] = (
                handshake_struct
            )
            self.handshake_msg_bytes_list.append(
                tls_plaintext_record.fragment
            )
            self.xtls.send_reply(
                handshake_struct.msg_type,
                self.handshake_msg_store,
                self.handshake_msg_bytes_list,
                self.write_to_wire_callback
            )

    def data_from_application(self, output):
        """
        Encrypt application data and send. This is only useful in APP_DATA
        state.
        """
        # encrypted_output = encrypt_output_bytes_w_negotiated_cipher_suite
        # self.write_to_wire_callback(encrypted_output)
        pass
