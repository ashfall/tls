from tls._buffer import HandshakeBuffer

from tls.record import parse_tls_plaintext


class TestHandshakeFragmentBuffer(object):

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
        b'\x00\x08'  # extensions length
        b'\x00\x0D'  # extensions.extensions.extension_type
        b'\x00\x04'  # extensions.extensions.extensions_data length
        b'abcd'  # extensions.extensions.extension_data
    )

    client_hello_handshake_packet = (
        b'\x01'  # msg_type
        b'\x00\x00\x003'  # body length
    ) + client_hello_packet

    tls_plaintext_packet = (
        b'\x16'  # type
        b'\x03'  # major version
        b'\x03'  # minor version
        b'\x008'  # big-endian length
    ) + client_hello_handshake_packet

    def test_no_fragmentation(self):
        """
        The case when the handshake struct is not fragmented, and is carried in
        in a TLSPlaintext message.
        """
        self.eb_flag = False
        self.cb_flag = False

        def check_handshake_message(hs_bytes):
            self.cb_flag = True
            assert hs_bytes == self.client_hello_handshake_packet

        def errback_insufficient_info():
            self.eb_flag = True

        tls_plaintext_record = parse_tls_plaintext(self.tls_plaintext_packet)
        buff = HandshakeBuffer(check_handshake_message,
                               errback_insufficient_info)
        buff.buffer_handshake_if_fragmented(tls_plaintext_record)
        assert self.cb_flag
        assert self.eb_flag is False

    def test_fragmented_message(self):
        """
        Put together the Handshake struct when it is fragmented *after* the
        "body length" field.
        """
        self.eb_flag = False
        self.cb_flag = False

        def check_handshake_message(hs_bytes):
            self.cb_flag = True
            assert hs_bytes == self.client_hello_handshake_packet

        def errback_insufficient_info():
            self.eb_flag = True

        tls_plaintext_packet_fragment_1 = (
            b'\x16'     # type
            b'\x03'     # major version
            b'\x03'     # minor version
            b'\x00\x06'       # length of fragment
        ) + self.client_hello_handshake_packet[:6]
        # includes msg_type + body length + 1 byte of the body

        tls_plaintext_packet_fragment_2 = (
            b'\x16'     # type
            b'\x03'     # major version
            b'\x03'     # minor version
            b'\x002'       # length of fragment
        ) + self.client_hello_handshake_packet[6:]

        tls_plaintext_record_1 = parse_tls_plaintext(
            tls_plaintext_packet_fragment_1
        )
        tls_plaintext_record_2 = parse_tls_plaintext(
            tls_plaintext_packet_fragment_2
        )

        buff = HandshakeBuffer(check_handshake_message,
                               errback_insufficient_info)
        buff.buffer_handshake_if_fragmented(tls_plaintext_record_1)
        assert self.cb_flag is False
        buff.buffer_handshake_if_fragmented(tls_plaintext_record_2)
        assert self.cb_flag
        assert self.eb_flag is False

    def test_insufficient_info_in_fragment(self):
        self.eb_flag = False
        self.cb_flag = False

        def check_handshake_message(hs_bytes):
            self.cb_flag = True
            assert hs_bytes == self.client_hello_handshake_packet

        def errback_insufficient_info():
            self.eb_flag = True

        tls_plaintext_packet = (
            b'\x16'     # type
            b'\x03'     # major version
            b'\x03'     # minor version
            b'\x00\x04'       # length of fragment
        ) + self.client_hello_handshake_packet[:4]

        tls_plaintext_record = parse_tls_plaintext(tls_plaintext_packet)
        buff = HandshakeBuffer(check_handshake_message,
                               errback_insufficient_info)
        buff.buffer_handshake_if_fragmented(tls_plaintext_record)
        assert self.cb_flag is False
        assert self.eb_flag

    def test_3_fragments(self):
        """
        When the handshake struct is split into more than 2 fragments.
        XXX: Is this even possible?
        """
        self.eb_flag = False
        self.cb_flag = False

        def check_handshake_message(hs_bytes):
            self.cb_flag = True
            assert hs_bytes == self.client_hello_handshake_packet

        def errback_insufficient_info():
            self.eb_flag = True

        tls_plaintext_packet_fragment_1 = (
            b'\x16'     # type
            b'\x03'     # major version
            b'\x03'     # minor version
            b'\x00\x06'       # length of fragment
        ) + self.client_hello_handshake_packet[:6]
        # includes msg_type + body length + 1 byte of the body

        tls_plaintext_packet_fragment_2 = (
            b'\x16'     # type
            b'\x03'     # major version
            b'\x03'     # minor version
            b'\x00.'       # length of fragment
        ) + self.client_hello_handshake_packet[6:-4]

        tls_plaintext_packet_fragment_3 = (
            b'\x16'     # type
            b'\x03'     # major version
            b'\x03'     # minor version
            b'\x00\x04'       # length of fragment
        ) + self.client_hello_handshake_packet[-4:]

        tls_plaintext_record_1 = parse_tls_plaintext(
            tls_plaintext_packet_fragment_1
        )
        tls_plaintext_record_2 = parse_tls_plaintext(
            tls_plaintext_packet_fragment_2
        )
        tls_plaintext_record_3 = parse_tls_plaintext(
            tls_plaintext_packet_fragment_3
        )

        buff = HandshakeBuffer(check_handshake_message,
                               errback_insufficient_info)
        buff.buffer_handshake_if_fragmented(tls_plaintext_record_1)
        assert self.cb_flag is False
        assert self.eb_flag is False
        buff.buffer_handshake_if_fragmented(tls_plaintext_record_2)
        assert self.cb_flag is False
        assert self.eb_flag is False
        buff.buffer_handshake_if_fragmented(tls_plaintext_record_3)
        assert self.cb_flag
        assert self.eb_flag is False
