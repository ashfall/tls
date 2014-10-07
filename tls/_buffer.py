import struct

from tls.record import ContentType

HANDSHAKE_MESSAGE_LENGTH_START_INDEX = 1
HANDSHAKE_BODY_START_INDEX = 5


class HandshakeBuffer(object):
    def __init__(self, call_with_complete_handshake_message):
        self.handshake_bytes = b''
        self.waiting_for_next_fragment = False
        self.call_with_complete_handshake_message = call_with_complete_handshake_message

    def buffer_handshake_if_fragmented(self, tls_plaintext):
        type = tls_plaintext.type
        fragment = tls_plaintext.fragment
        buffer_bytes = b''
        if type == ContentType.HANDSHAKE and fragment:
            if self.waiting_for_next_fragment:
                self.handshake_bytes += fragment
                if len(self.handshake_bytes) == self.handshake_message_length:
                    # We have the complete handshake bytes in our buffer, can
                    # parse now
                    self.waiting_for_next_fragment = False
                    self.call_with_complete_handshake_message(self.handshake_bytes)
            else:
                self.handshake_bytes = b''
                handshake_message_type = fragment[:HANDSHAKE_MESSAGE_LENGTH_START_INDEX]
                self.handshake_message_length = fragment[HANDSHAKE_MESSAGE_LENGTH_START_INDEX:HANDSHAKE_BODY_START_INDEX]
                handshake_body = fragment[HANDSHAKE_BODY_START_INDEX:]
                self.handshake_bytes += fragment
                if len(handshake_body) < struct.unpack("!I", self.handshake_message_length)[0]:
                    self.waiting_for_next_fragment = True
                else:
                    self.call_with_complete_handshake_message(self.handshake_bytes)

