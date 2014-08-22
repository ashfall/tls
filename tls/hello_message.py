from __future__ import absolute_import, division, print_function

from enum import Enum

from characteristic import attributes

from tls import _constructs


# @attributes([])
class HelloRequest(object):
    """
    An object representing a HelloRequest message.
    """


@attributes(['major', 'minor'])
class ClientVersion(object):
    """
    An object representing a ClientVersion struct.
    """


@attributes(['gmt_unix_time', 'random_bytes'])
class Random(object):
    """
    An object representing a Random struct.
    """


# TODO: Figure out what to do about extensions present
@attributes(['client_version', 'random', 'session_id', 'cipher_suites',
             'compression_methods'])
class ClientHello(object):
    """
    An object representing a ClientHello message.
    """


def parse_hello_request():
    """
    Parse a ``HelloRequest`` struct.
    """
#    construct = _constructs.HelloRequest.parse() # Do we relly need this?
    return HelloRequest()


class CompressionMethod(Enum):
    NULL = 0


def parse_client_hello(bytes):
    """
    Parse a ``ClientHello`` struct.

    :param bytes: the bytes representing the input.
    :return: ClientHello object.
    """
    construct = _constructs.ClientHello.parse(bytes)
    return ClientHello(
        client_version=ClientVersion(
            major=construct.client_version.major,
            minor=construct.client_version.minor,
        ),
        random=Random(
            gmt_unix_time=construct.random.gmt_unix_time,
            random_bytes=construct.random.random_bytes,
        ),
        session_id=construct.session_id,
        cipher_suites=construct.cipher_suites,
        compression_methods=CompressionMethod(construct.compression_methods),
    )
