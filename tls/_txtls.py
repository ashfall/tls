
from twisted.internet.endpoints import HostnameEndpoint


class _TLSTransport(...):
    def write(self, data):
        self._tls_proto._connection.write_data(data)


class _TLSProtocol(Protocol):
    def __init__(self, app_protocol, tls):
        self._tls = tls
    def connectionMade(self):
        self._connection = self._tls.start(self.transport.write, self.transport.abortConnection)
    def dataReceived(self, data):
        app_data = self._connection.receive_data(data)
        if app_data:
            self._app_protocol.dataReceived(app_data)
    def connectionLost(self, reason):
        self._sub_protocol.connectionLost(
            self._figure_out_if_close_alert_is_ok(reason))

class _TLSFactory(Factory):
    def buildProtocol(self, addr):
        return _TLSProtocol(self.factory.buildProtocol(addr), self._tls)

class TLSClientEndpoint(object):
    def __init__(self, clientTLS, subendpoint):
        self._tls = clientTLS
        self._endpoint = subendpoint

    @classmethod
    def to_hostname(cls, a_hostname, port, trust_root, client_certificate_store=None):
        return cls(HostnameEndpoint(a_hostname, port), ClientTLS(a_hostname, trust_root, ...))
    def connect(self, factory):
        return self._endpoint.connect(_TLSFactory(self._tls, factory)).addCallback(lambda tlsProtocol: wrapperProtocol.actualProtocol)

