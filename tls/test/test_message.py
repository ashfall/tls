# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from construct.adapters import ValidationError

from cryptography import x509

import pytest

from tls._common import enums

from tls.exceptions import BadCertificateException, TLSValidationException

from tls.hello_message import ClientHello, ProtocolVersion, ServerHello

from tls.message import (ASN1Cert, Certificate, CertificateRequest,
                         CertificateStatus, CertificateURL, Finished,
                         Handshake, HelloRequest, PreMasterSecret,
                         ServerDHParams, ServerHelloDone, URLAndHash)


class TestCertificateRequestParsing(object):
    """
    Tests for parsing of CertificateRequest messages.
    """
    no_authorities_packet = (
        b'\x01'  # certificate_types length
        b'\x01'  # certificate_types
        b'\x00\x02'  # supported_signature_algorithms length
        b'\x01'  # supported_signature_algorithms.hash
        b'\x01'  # supported_signature_algorithms.signature
        b'\x00\x00'  # certificate_authorities length
        b''  # certificate_authorities
    )
    with_authorities_packet = (
        b'\x01'  # certificate_types length
        b'\x01'  # certificate_types
        b'\x00\x02'  # supported_signature_algorithms length
        b'\x01'  # supported_signature_algorithms.hash
        b'\x01'  # supported_signature_algorithms.signature
        b'\x00\x02'  # certificate_authorities length
        b'03'  # certificate_authorities
    )
    certificate_types_too_short = (
        b'\x00'  # certificate_types length
        b''  # certificate_types
        b''  # supported_signature_algorithms length
        b''  # supported_signature_algorithms.hash
        b''  # supported_signature_algorithms.signature
        b''  # certificate_authorities length
        b''  # certificate_authorities
    )
    supported_signature_algorithms_too_short = (
        b'\x01'  # certificate_types length
        b'\x01'  # certificate_types
        b'\x00\x00'  # supported_signature_algorithms length
        b''  # supported_signature_algorithms.hash
        b''  # supported_signature_algorithms.signature
        b''  # certificate_authorities length
        b''  # certificate_authorities
    )

    def test_parse_certificate_request(self):
        record = CertificateRequest.from_bytes(self.no_authorities_packet)
        assert record.certificate_types == [
            enums.ClientCertificateType.RSA_SIGN
        ]
        assert len(record.supported_signature_algorithms) == 1
        assert (record.supported_signature_algorithms[0].hash ==
                enums.HashAlgorithm.MD5)
        assert (record.supported_signature_algorithms[0].signature ==
                enums.SignatureAlgorithm.RSA)
        assert record.certificate_authorities == b''

    def test_parse_certificate_request_with_authorities(self):
        record = CertificateRequest.from_bytes(self.with_authorities_packet)
        assert record.certificate_authorities == b'03'

    def test_as_bytes_no_authoritites(self):
        record = CertificateRequest.from_bytes(self.no_authorities_packet)
        assert record.as_bytes() == self.no_authorities_packet

    def test_as_bytes_with_authoritites(self):
        record = CertificateRequest.from_bytes(self.with_authorities_packet)
        assert record.as_bytes() == self.with_authorities_packet

    def test_parse_certificate_types_too_short(self):
        """
        :py:func:`tls.message.CertificateRequest` fails to parse a
        certificate request packet whose ``certificate_types`` is too
        short.
        """
        with pytest.raises(ValidationError) as exc_info:
            CertificateRequest.from_bytes(self.certificate_types_too_short)
        assert exc_info.value.args == ('invalid object', 0)

    def test_as_bytes_certificate_types_too_short(self):
        """
        :py:func:`tls.message.CertificateRequest` fails to construct a
        certificate request packet whose ``certificate_types`` would
        be too short.
        """
        record = CertificateRequest.from_bytes(self.no_authorities_packet)
        record.certificate_types = []
        with pytest.raises(ValidationError) as exc_info:
            record.as_bytes()
        assert exc_info.value.args == ('invalid object', 0)

    def test_parse_supported_signature_algorithms_too_short(self):
        """
        :py:func:`CertificateRequest` fails to parse a certificate
        request packet whose ``supported_signature_algorithms`` is too
        short.
        """
        with pytest.raises(ValidationError) as exc_info:
            CertificateRequest.from_bytes(
                self.supported_signature_algorithms_too_short)
        assert exc_info.value.args == ('invalid object', 0)

    def test_as_bytes_supported_signature_algorithms_too_short(self):
        """
        :py:func:`CertificateRequest` fails to construct a certificate
        request packet whose ``supported_signature_algorithms`` would
        be too short.
        """
        record = CertificateRequest.from_bytes(self.no_authorities_packet)
        record.supported_signature_algorithms = []
        with pytest.raises(ValidationError) as exc_info:
            record.as_bytes()
        assert exc_info.value.args == ('invalid object', 0)


class TestServerDHParamsParsing(object):
    """
    Tests for parsing of ServerDHParams struct.
    """

    def test_parse_struct(self):
        packet = (
            b'\x00\x03'
            b'123'
            b'\x00\x04'
            b'5678'
            b'\x00\x02'
            b'78'
        )
        record = ServerDHParams.from_bytes(packet)
        assert record.dh_p == b'123'
        assert record.dh_g == b'5678'
        assert record.dh_Ys == b'78'


class TestPreMasterSecretParsing(object):
    """
    Tests for parsing of PreMasterSecret struct.
    """

    def test_parse_pre_master_secret(self):
        import os
        r = os.urandom(46)
        packet = (
            b'\x03\x00' + r  # ClientHello.client_version + random
        )
        record = PreMasterSecret.from_bytes(packet)
        assert isinstance(record, PreMasterSecret)
        assert isinstance(record.client_version, ProtocolVersion)
        assert record.client_version.major == 3
        assert record.client_version.minor == 0
        assert record.random == r


class TestASN1Certificate(object):
    """
    Tests for serializing :py:class:`tls.message.ASN1Cert`
    """
    good_cert = (
        b'0\x82\x04\x800\x82\x03h\xa0\x03\x02\x01\x02\x02\x08!@\x15\x1d\x89\xf1\xa3\x1a0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000I1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x13\nGoogle Inc1%0#\x06\x03U\x04\x03\x13\x1cGoogle Internet Authority G20\x1e\x17\r170118185000Z\x17\r170412185000Z0h1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x0c\nCalifornia1\x160\x14\x06\x03U\x04\x07\x0c\rMountain View1\x130\x11\x06\x03U\x04\n\x0c\nGoogle Inc1\x170\x15\x06\x03U\x04\x03\x0c\x0ewww.google.com0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xcdE\xc4\xb3\xd6k[\xff\x92v\xe9\xaa\xe9\x98\x18\x82\x99#n\xbb\x05\xd3r\xfa\x1f\xd2\xfb\xeb\x0b\x8bB\xfaR!z>x\xf1\x89\xd0\xabD2C%\xef\'\x0f\xb2\xb0i\xc5\x80\xf2\x05\t\xdf)K\x86s\x07\xd4B)n\\\xf5f\x07\xebzL\xed\xb9/\xbc\x9a\x91\xd3\xc0\xdb\xd9\xd8u\xc7\xa4\xb5\x86\x94_}^\xbc\xc7\x9e\xf6\xc5z\xf5\xce\xd1\x00\x8e\xd3XO\xbc\xb2d~\x11t\x80\x7f7vm\x84\x89RQ\xee\'Z\xc0\x013\x1d\x86\xe5x\x91\x91\xe3\xa7\x8bU>\xdb\xc2_\x8d\x07\x9f\x81?\x94Z\x86\xb6uQ-\xf7r2\x9c\x91\x06\xca\xfe\xc9\xf5S\xd2\xfc\x98\xf9\xc5\xbe\xcdC\n\x89r\xa6Pg\xad\xee\xd4\xe6+\n\xf7\xf8\xde\xb7qx\xc0\x81\x8f\\\xf6\x1d\x15\x85\xebL\x07&\x0c\xd5\x81L\xefa\xe4\xf6"\x9b\xdb\x1eF\x0eX\xa5\xebvQ\xf1F\xdf\x90X~\xd7\x89=\xdb\x87\xfc\x81\x99\r\xb6\x80\xe0\xad\x8d\x91&\xa7%\xbbX_\xec\xb41@\xe3\x99\x9b\x02\x03\x01\x00\x01\xa3\x82\x01K0\x82\x01G0\x1d\x06\x03U\x1d%\x04\x160\x14\x06\x08+\x06\x01\x05\x05\x07\x03\x01\x06\x08+\x06\x01\x05\x05\x07\x03\x020\x19\x06\x03U\x1d\x11\x04\x120\x10\x82\x0ewww.google.com0h\x06\x08+\x06\x01\x05\x05\x07\x01\x01\x04\\0Z0+\x06\x08+\x06\x01\x05\x05\x070\x02\x86\x1fhttp://pki.google.com/GIAG2.crt0+\x06\x08+\x06\x01\x05\x05\x070\x01\x86\x1fhttp://clients1.google.com/ocsp0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\x99z\x8c\xf8\xccu\x81\xdd9\xf4\xb9\xd1\x8e\xa6\xa7\xcb\xf1&^\xfa0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14J\xdd\x06\x16\x1b\xbc\xf6h\xb5v\xf5\x81\xb6\xbbb\x1a\xbaZ\x81/0!\x06\x03U\x1d \x04\x1a0\x180\x0c\x06\n+\x06\x01\x04\x01\xd6y\x02\x05\x010\x08\x06\x06g\x81\x0c\x01\x02\x0200\x06\x03U\x1d\x1f\x04)0\'0%\xa0#\xa0!\x86\x1fhttp://pki.google.com/GIAG2.crl0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x1aLb\x18?\xda5\x9f?M^l\xfe\x06\xe8A\xbd\xc8\x80\xd8\xa30\x86\x9c\xb6\xaf\x96\xf2\xcc\x11X\xa4\xd9\xd8\xde\xae?o\x95\x17\x8f\xc2\x9a\xa6\xe5O\xbd\xe4\x86v)\x8c\xca\xc90\xf8\x11\xc9v1\xa6\xc73z\xdao\x17E\xa6QUc\x0c\xbc\x81\xf2\xb1\xd9v\xd3\x12\xce \xad\xd8\x96c\xe9#\x12Y\xa18\x12\xdb\x86P\xc2\xb1\x87\x81\x89\x1bGi5\xfd\x00\x8c\x11f6\x0f\x1d\xe3\xddE\xecld\xa7U\xea$\xfd\xe0U\xe3\xa0\xe7b\x84\xcc\xf1\xb2L\xf46@TFx\x93\xbat?\xf4}\xbf\xf0\x9cA2\x05\x0e\x8e\x9d\xf2\xed\xae\xdd\rf\x1e\xf8\xa3\xfe\xf7\r\x7f\xf4\xcaTo[\x06\x19f\xd6\xf8;\xa3\xf6\xc3\xa4\xbd-\xf6\xad\x089\x81)\xc6\xb4Aug\x14\x04\x0c\x16\x83\x13\x16\xaa\xc6,Zp\x8c4\x9e\'\x0c\x1ck\xd3\x83\xe2@\x89\x959\x9d<=\x8c\n\xca]\x91W\xba\xe8\x84\xf8\x91\xb7\xf7\x03\x96T\x9bd?Q\xe2\x81_fq\xd8wt\xc2'
    )

    asn1_cert_bytes = (
        b'\x00\x04\x84'  # ASN1Cert.length
    ) + good_cert  # ASN1Cert.asn1_cert


    def test_from_bytes(self):
        """

        """
        record = ASN1Cert.from_bytes(self.asn1_cert_bytes)
        assert isinstance(record, ASN1Cert)
        assert isinstance(record.asn1_cert, x509.Certificate)


    def test_as_bytes(self):
        """
        :py:meth:`tls.message.ASN1Cert.as_bytes` constructs a valid
        packet.
        """
        record = ASN1Cert.from_bytes(self.asn1_cert_bytes)
        assert record.as_bytes() == self.asn1_cert_bytes

    def test_as_bytes_bad_cert(self):
        """
        :py:meth:`tls.message.ASN1Cert.as_bytes` fails to construct a
        packet whose ``asn1_cert`` contains bad X509 bytes.
        """
        record = ASN1Cert.from_bytes(self.asn1_cert_bytes)
        record.asn1_cert = b"abcd"
        with pytest.raises(BadCertificateException):
            record.as_bytes()

    def test_from_bytes_bad_cert(self):
        """
        :py:meth:`tls.message.ASN1Cert.from_bytes` raises a
        ``BadCertificateException`` when corrupted certificate bytes are used.
        "corrupted" here means values that ``cryptography.x509`` fails to load
        as a ``x509.Certificate``.
        """
        bad_packet = (
            b'\x00\x00\x04'  # ASN1Cert.length
            b'abcd'  # ASN1Cert.asn1_cert
        )
        with pytest.raises(BadCertificateException):
            ASN1Cert.from_bytes(bad_packet)


class TestCertificateParsing(object):
    """
    Tests for parsing of :py:class:`tls.message.Certificate` messages.
    """

    packet = (
        b'\x00\x00\x06'  # certificate_length
        b'\x00\x00\x03'  # certificate_list.asn1_cert length
        b'ABC'  # certificate_list.asn1_cert
    )


    good_certs_packet = (
        b'\x00\x0c\x02'  # certificate_list_len
    )

    certificates_too_short = (
        b'\x00\x00\x00'  # certificate_length
        b''  # certificate_list.asn1_cert length
        b''  # certificate_list.asn1_cert
    )

    def test_parse_certificate(self):
        """
        :py:meth:`tls.message.Certificate.from_bytes` parses a valid
        packet.
        """

        import pdb; pdb.set_trace()
        record = Certificate.from_bytes(self.packet)
        assert isinstance(record, Certificate)
        assert len(record.certificate_list) == 1
        assert record.certificate_list[0].asn1_cert == b'ABC'

    def test_as_bytes(self):
        """
        :py:meth:`tls.message.Certificate.as_bytes` returns a valid
        packet.
        """
        record = Certificate.from_bytes(self.packet)
        assert record.as_bytes() == self.packet

    def test_parse_certificate_too_short(self):
        """
        :py:meth:`tls.message.Certificate.from_bytes` rejects a packet
        whose ``certificate_list`` is too short.
        """
        with pytest.raises(ValidationError):
            Certificate.from_bytes(self.certificates_too_short)

    def test_as_bytes_too_short(self):
        """
        :py:meth:`tls.message.Certificate.as_bytes` fails to construct
        a packet whose ``certificate_list`` would be too long.
        """
        certificate = Certificate.from_bytes(self.packet)
        certificate.certificate_list = []
        with pytest.raises(ValidationError):
            certificate.as_bytes()

    def test_as_bytes_too_long(self):
        """
        :py:meth:`tls.message.Certificate.as_bytes` fails to construct
        a packet whose ``certificate_list`` would be too short.
        """
        certificate = Certificate.from_bytes(self.packet)
        # this is kind of a cheat: the length of the packet ends up
        # being too large, but not because there are too many
        # ASN1Certs.  there's only one very large ASN1Cert.
        certificate.certificate_list = [ASN1Cert(b'a' * 0x1000000)]
        with pytest.raises(ValidationError):
            certificate.as_bytes()


class TestCertificateURLParsing(object):
    """
    Tests for parsing of :py:class:`tls.message.CertificateURL` messages.
    """
    url_and_hash_list_bytes = (
        b'\x00\x10'  # url length
        b'cert.example.com'  # url
        b'\x01'  # padding
        b'abcdefghijklmnopqrst'  # SHA1Hash[20]
    )

    certificate_url_packet = (
        b'\x00'  # CertChainType
        b'\x00\x27'  # url_and_hash_list length
    ) + url_and_hash_list_bytes

    def test_parse_certificate_url(self):
        """
        :py:meth:`tls.message.CertificateURL.from_bytes` parses a valid
        packet.
        """
        record = CertificateURL.from_bytes(self.certificate_url_packet)
        assert isinstance(record, CertificateURL)
        assert record.type == enums.CertChainType.INDIVIDUAL_CERTS
        assert len(record.url_and_hash_list) == 1
        assert record.url_and_hash_list[0].url == b'cert.example.com'
        assert record.url_and_hash_list[0].padding == 1
        assert record.url_and_hash_list[0].sha1_hash == b'abcdefghijklmnopqrst'

    def test_incorrect_padding_parsing(self):
        """
        :py:meth:`tls._constructs.URLAndHash.parse` rejects a packet
        whose ``padding`` is not 1.
        """
        bad_padding_bytes = (
            b'\x00\x10'  # url length
            b'cert.example.com'  # url
            b'\x03'  # padding
            b'abcdefghijklmnopqrst'  # SHA1Hash[20]
        )

        certificate_url_packet = (
            b'\x00'  # CertChainType
            b'\x00\x27'  # url_and_hash_list length
        ) + bad_padding_bytes

        with pytest.raises(TLSValidationException) as exc_info:
            CertificateURL.from_bytes(certificate_url_packet)

        assert exc_info.value.args == ('object failed validation', 3)

    def test_as_bytes(self):
        """
        :py:meth:`tls.message.CertificateUrl.as_bytes` returns a valid
        packet.
        """
        record = CertificateURL.from_bytes(self.certificate_url_packet)
        assert record.as_bytes() == self.certificate_url_packet

    def test_as_bytes_with_bad_padding(self):
        """
        :py:meth:`tls.message.CertificateURL.as_bytes` fails to serialize  a
        record whose ``padding`` is not 1.
        """
        record = CertificateURL.from_bytes(self.certificate_url_packet)
        record.url_and_hash_list[0].padding = 5
        with pytest.raises(TLSValidationException):
            record.as_bytes()

    def test_url_and_hash_list_too_short(self):
        """
        :py:class:`tls._constructs.CertificateURL` rejects
        a record where length of `url_and_hash_list` is
        less than 1.
        """
        record = CertificateURL.from_bytes(self.certificate_url_packet)
        record.url_and_hash_list = []
        with pytest.raises(ValidationError) as exc_info:
            record.as_bytes()

        assert exc_info.value.args == ('invalid object', 0)


class TestCertificateStatusParsing(object):
    """
    Tests for parsing of
    :py:class:`tls.message.CertificateStatus` structs.
    """
    certificate_status = (
        b'\x01'  # status_type
        b'\x00\x00\x05'  # response length
        b'12345'  # response
    )

    def test_from_bytes(self):
        """
        :py:meth:`tls.message.CertificateStatus.from_bytes` parses a valid
        packet.
        """
        record = CertificateStatus.from_bytes(self.certificate_status)
        assert isinstance(record, CertificateStatus)
        assert record.status_type == enums.CertificateStatusType.OCSP
        assert record.response == b'12345'

    def test_as_bytes(self):
        """
        :py:meth:`tls.message.CertificateStatus.as_bytes` returns the bytes it
        was created with.
        """
        record = CertificateStatus.from_bytes(self.certificate_status)
        assert record.as_bytes() == self.certificate_status


class TestHandshakeStructParsing(object):
    """
    Tests for parsing of :py:class:`tls.message.Handshake` structs.
    """
    supported_signature_list_extension_data = (
        b'\x00\x0D'  # extensions[0].extension_type
        b'\x00\x16'  # extensions[0].length
        b'\x00\x14'  # The length of signature_algorithms vector
        b'\x04\x01'  # SHA256, RSA
        b'\x05\x01'  # SHA384, RSA
        b'\x06\x01'  # SHA512, RSA
        b'\x02\x01'  # SHA1, RSA
        b'\x04\x03'  # SHA256, ECDSA
        b'\x05\x03'  # SHA384, ECDSA
        b'\x06\x03'  # SHA512, ECDSA
        b'\x02\x03'  # SHA1, ECDSA
        b'\x04\x02'  # SHA256, DSA
        b'\x02\x02'  # SHA1, DSA
    )

    client_hello_packet = (
        b'\x03\x00'  # client_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x00'  # session_id.length
        b''  # session_id.session_id
        b'\x00\x02'  # cipher_suites length
        b'\x00\x6B'  # cipher_suites
        b'\x01'  # compression_methods length
        b'\x00'  # compression_methods
        b'\x00\x1a'  # extensions length
    ) + supported_signature_list_extension_data

    client_hello_handshake_packet = (
        b'\x01'  # msg_type
        b'\x00\x00\x45'  # body length
    ) + client_hello_packet

    server_hello_packet = (
        b'\x03\x00'  # server_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x20'  # session_id.length
        b'01234567890123456789012345678901'  # session_id
        b'\x00\x6B'  # cipher_suite
        b'\x00'  # compression_method
        b'\x00\x00'  # extensions.length
    )

    server_hello_handshake_packet = (
        b'\x02'  # msg_type
        b'\x00\x00\x48'  # body length
    ) + server_hello_packet

    certificate_packet = (
        b'\x00\x00\x06'  # certificate_length
        b'\x00\x00\x03'  # certificate_list.asn1_cert length
        b'ABC'  # certificate_list.asn1_cert
    )

    certificate_handshake_packet = (
        b'\x0B'
        b'\x00\x00\x09'
    ) + certificate_packet

    certificate_request_packet = (
        b'\x01'  # certificate_types length
        b'\x01'  # certificate_types
        b'\x00\x02'  # supported_signature_algorithms length
        b'\x01'  # supported_signature_algorithms.hash
        b'\x01'  # supported_signature_algorithms.signature
        b'\x00\x00'  # certificate_authorities length
        b''  # certificate_authorities
    )

    certificate_request_handshake = (
        b'\x0D'
        b'\x00\x00\x08'
    ) + certificate_request_packet

    server_key_exchange_handshake = (
        b'\x0C'
        b'\x00\x00\x00'
        b''
    )

    hello_request_handshake = (
        b'\x00'
        b'\x00\x00\x00'
        b''
    )

    server_hello_done_handshake = (
        b'\x0E'
        b'\x00\x00\x00'
        b''
    )

    finished_handshake = (
        b'\x14'
        b'\x00\x00\x14'
        b'some-encrypted-bytes'
    )

    certificate_url_packet = (
        b'\x00'  # CertChainType
        b'\x00\x27'  # url_and_hash_list length
        b'\x00\x10'  # url length
        b'cert.example.com'  # url
        b'\x01'  # padding
        b'abcdefghijklmnopqrst'  # SHA1Hash[20]
    )

    certificate_url_handshake_packet = (
        b'\x15'
        b'\x00\x00\x2a'
    ) + certificate_url_packet

    certificate_status = (
        b'\x01'  # status_type
        b'\x00\x00\x05'  # response length
        b'12345'  # response
    )

    certificate_status_handshake = (
        b'\x16'  # handshake msg type
        b'\x00\x00\x09'  # handshake body length
    ) + certificate_status

    def test_parse_client_hello_in_handshake(self):
        record = Handshake.from_bytes(self.client_hello_handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.CLIENT_HELLO
        assert record.length == 69
        assert isinstance(record.body, ClientHello)

    def test_parse_server_hello_in_handshake(self):
        record = Handshake.from_bytes(self.server_hello_handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.SERVER_HELLO
        assert record.length == 72
        assert isinstance(record.body, ServerHello)

    def test_parse_certificate_request_in_handshake(self):
        record = Handshake.from_bytes(
            self.certificate_request_handshake
        )
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.CERTIFICATE_REQUEST
        assert record.length == 8
        assert isinstance(record.body, CertificateRequest)

    def test_parse_certificate_in_handshake(self):
        record = Handshake.from_bytes(self.certificate_handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.CERTIFICATE
        assert record.length == 9
        assert isinstance(record.body, Certificate)

    def test_parse_hello_request(self):
        record = Handshake.from_bytes(self.hello_request_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.HELLO_REQUEST
        assert record.length == 0
        assert isinstance(record.body, HelloRequest)

    def test_server_hello_done(self):
        record = Handshake.from_bytes(self.server_hello_done_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.SERVER_HELLO_DONE
        assert record.length == 0
        assert isinstance(record.body, ServerHelloDone)

    def test_not_implemented(self):
        record = Handshake.from_bytes(self.server_key_exchange_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.SERVER_KEY_EXCHANGE
        assert record.length == 0
        assert record.body is None

    def test_finished(self):
        record = Handshake.from_bytes(self.finished_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.FINISHED
        assert record.length == 20
        assert isinstance(record.body, Finished)
        assert record.body.verify_data == b'some-encrypted-bytes'

    def test_as_bytes_server_hello_packet(self):
        record = Handshake.from_bytes(self.server_hello_handshake_packet)
        assert record.as_bytes() == self.server_hello_handshake_packet

    def test_as_bytes_client_hello_packet(self):
        record = Handshake.from_bytes(self.client_hello_handshake_packet)
        assert record.as_bytes() == self.client_hello_handshake_packet

    def test_as_bytes_certificate_packet(self):
        record = Handshake.from_bytes(self.certificate_handshake_packet)
        assert record.as_bytes() == self.certificate_handshake_packet

    def test_as_bytes_certificate_request_packet(self):
        record = Handshake.from_bytes(self.certificate_request_handshake)
        assert record.as_bytes() == self.certificate_request_handshake

    def test_as_bytes_not_implemented(self):
        record = Handshake.from_bytes(self.server_key_exchange_handshake)
        assert record.as_bytes() == self.server_key_exchange_handshake

    def test_as_bytes_hello_request(self):
        record = Handshake.from_bytes(self.hello_request_handshake)
        assert record.as_bytes() == self.hello_request_handshake

    def test_as_bytes_server_hello_done(self):
        record = Handshake.from_bytes(self.server_hello_done_handshake)
        assert record.as_bytes() == self.server_hello_done_handshake

    def test_as_bytes_finished(self):
        record = Handshake.from_bytes(self.finished_handshake)
        assert record.as_bytes() == self.finished_handshake

    def test_from_bytes_certificate_url(self):
        """
        :py:class:`tls.message.Handshake` parses a valid packet with a
        ``CertificateURL`` message.
        """
        record = Handshake.from_bytes(self.certificate_url_handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.CERTIFICATE_URL
        assert record.length == 42
        assert isinstance(record.body, CertificateURL)
        assert record.body.type == enums.CertChainType.INDIVIDUAL_CERTS
        assert len(record.body.url_and_hash_list) == 1
        assert isinstance(record.body.url_and_hash_list[0], URLAndHash)
        assert record.body.url_and_hash_list[0].url == b'cert.example.com'
        assert record.body.url_and_hash_list[0].padding == 1
        assert (record.body.url_and_hash_list[0].sha1_hash ==
                b'abcdefghijklmnopqrst')

    def test_as_bytes_certificate_url(self):
        """
        :py:meth:`tls.message.Handshake.as_bytes` returns a valid packet when
        the body contains a ``CertificateURL`` message.
        """
        record = Handshake.from_bytes(self.certificate_url_handshake_packet)
        assert record.as_bytes() == self.certificate_url_handshake_packet

    def test_from_bytes_certificate_status(self):
        """
        :py:class:`tls.message.Handshake` parses a valid packet with
        ``CertificateStatus`` message.
        """
        record = Handshake.from_bytes(self.certificate_status_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == enums.HandshakeType.CERTIFICATE_STATUS
        assert record.length == 9
        assert isinstance(record.body, CertificateStatus)
        assert record.body.status_type == enums.CertificateStatusType.OCSP
        assert record.body.response == b'12345'

    def test_as_bytes_certificate_status(self):
        """
        :py:class:`tls.message.Handshake` serializes a record containing a
        ``CertificateStatus`` message.
        """
        record = Handshake.from_bytes(self.certificate_status_handshake)
        assert record.as_bytes() == self.certificate_status_handshake
