# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import attr

from construct import Container

from tls import _constructs

from tls._common import enums


@attr.s
class ProtocolVersion(object):
    """
    An object representing a ProtocolVersion struct.
    """
    major = attr.ib()
    minor = attr.ib()


@attr.s
class Random(object):
    """
    An object representing a Random struct.
    """
    gmt_unix_time = attr.ib()
    random_bytes = attr.ib()


@attr.s
class ClientHello(object):
    """
    An object representing a ClientHello message.
    """
    client_version = attr.ib()
    random = attr.ib()
    session_id = attr.ib()
    cipher_suites = attr.ib()
    compression_methods = attr.ib()
    extensions = attr.ib()

    def as_bytes(self):
        return _constructs.ClientHello.build(
            Container(
                version=Container(major=self.client_version.major,
                                  minor=self.client_version.minor),
                random=Container(
                    gmt_unix_time=self.random.gmt_unix_time,
                    random_bytes=self.random.random_bytes
                ),
                session_id=Container(length=len(self.session_id),
                                     session_id=self.session_id),
                cipher_suites=self.cipher_suites,
                compression_methods=Container(
                    length=len(self.compression_methods),
                    compression_methods=self.compression_methods
                ),
                extensions=b''.join(
                    [ext.as_bytes() for ext in self.extensions]
                )
            )
        )

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``ClientHello`` struct.

        :param bytes: the bytes representing the input.
        :return: ClientHello object.
        """
        construct = _constructs.ClientHello.parse(bytes)
        # XXX Is there a better way in Construct to parse an array of
        # variable-length structs?
        extensions = []
        if construct.extensions:
            extensions = _constructs.Extensions.parse(construct.extensions)

        return ClientHello(
            client_version=ProtocolVersion(
                major=construct.version.major,
                minor=construct.version.minor,
            ),
            random=Random(
                gmt_unix_time=construct.random.gmt_unix_time,
                random_bytes=construct.random.random_bytes,
            ),
            session_id=construct.session_id.session_id,
            cipher_suites=construct.cipher_suites,
            compression_methods=(
                construct.compression_methods.compression_methods
            ),
            extensions=extensions
        )


@attr.s
class ServerHello(object):
    """
    An object representing a ServerHello message.
    """
    server_version = attr.ib()
    random = attr.ib()
    session_id = attr.ib()
    cipher_suite = attr.ib()
    compression_method = attr.ib()
    extensions = attr.ib()

    def as_bytes(self):
        return _constructs.ServerHello.build(
            Container(
                version=Container(major=self.server_version.major,
                                  minor=self.server_version.minor),
                random=Container(
                    gmt_unix_time=self.random.gmt_unix_time,
                    random_bytes=self.random.random_bytes
                ),
                session_id=Container(length=len(self.session_id),
                                     session_id=self.session_id),
                cipher_suite=self.cipher_suite,
                compression_method=self.compression_method.value,
                extensions_length=sum([2 + 2 + len(ext.data)
                                       for ext in self.extensions]),
                extensions=b''.join(
                    [ext.as_bytes() for ext in self.extensions]
                )
            )
        )

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``ServerHello`` struct.

        :param bytes: the bytes representing the input.
        :return: ServerHello object.
        """
        construct = _constructs.ServerHello.parse(bytes)
        if construct.extensions:
            extensions = _constructs.Extensions.parse(construct.extensions)
        else:
            extensions = []

        return ServerHello(
            server_version=ProtocolVersion(
                major=construct.version.major,
                minor=construct.version.minor,
            ),
            random=Random(
                gmt_unix_time=construct.random.gmt_unix_time,
                random_bytes=construct.random.random_bytes,
            ),
            session_id=construct.session_id.session_id,
            cipher_suite=construct.cipher_suite,
            compression_method=enums.CompressionMethod(
                construct.compression_method
            ),
            extensions=extensions,
        )
