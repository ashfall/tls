from tls.record import parse_tls_plaintext

from tls._buffer import HandshakeBuffer


class TestHandshakeFragmentBuffer(object):

    def test_no_fragmentation(self):
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

        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x008'  # big-endian length
        ) + client_hello_handshake_packet

        tls_plaintext_record = parse_tls_plaintext(packet)
        buff = HandshakeBuffer()
        handshake_struct = buff.buffer_handshake_if_fragmented(tls_plaintext_record)
        assert handshake_struct == client_hello_handshake_packet


    def test_fragmented_message(self):
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

        packet_1 = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x008'  # big-endian length
        ) + client_hello_handshake_packet

        hs_packet_1 = packet[:6]
        hs_packet_2 = packet[6:]

