from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet import reactor


class TLSByteProtocol(Protocol):
    def dataReceived(self, data):


class ClientTLS(object):

    def __init__(self, server_hostname, trust_root, client_certificate_store=None):
        self.server_hostname = server_hostname
        self.trust_root = trust_root
        self.client_certificate_store = client_certificate_store

    def start(self, write_callback, close_callback, verify_callback=None):
        """
        Returns the client Connection.
        """
        conn = _InternalConnection(...)
        return (ApplicationConnection(conn),
                WireConnection(conn))


class ServerTLS(object):

    def __init__(self, certificates, dh_params=None):
        self.certificates = certificates
        self.dh_params = self.dh_params

    def start(self, write_callback, verify_callback=None):
        """
        Returns the server Connection.
        """

class ApplicationConnection(object):
    def write_data(self, output):
        """
        Write the Output bytes (application data) to encrypt and send over the transport.

        Given plaintext application data, invoke the write callback with the
        encrypted data.
        """
    def alert(self, alert_code, level=None):
        """
        Invoke the write callback with a TLS alert message. Usually this is
        invoked automatically by a method like receive_data, but it may be
        useful to call this in your verify_callback.
        """

    def finish(self):
        """
        Invoke the write callback with a TLSFinished message.
        """
        # XXX: Create/Build TLSFinished


class WireConnection(object):
    def receive_data(self, input):
        """
        Process the input bytes and return decrypted bytes, if any.
        If the input data is invalid, pass a TLSAlert message to the write callback and raise BadTLSDataError.
        """

        # xxx: Encrypt the output bytes

