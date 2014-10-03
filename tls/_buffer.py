import struct

from tls.record import ContentType

class HandshakeBuffer(object):
    def __init__(self, tls_plaintext):
        self.handshake_bytes = b''
        self.tls_plaintext = tls_plaintext
        self.waiting_for_next_fragment = False

    def buffer_handshake_if_fragmented(self):
        type = self.tls_plaintext.type
        fragment = self.tls_plaintext.fragment
        buffer_bytes = b''
        if type == ContentType.HANDSHAKE and fragment:
            if self.waiting_for_next_fragment:
                self.handshake_bytes += fragment
                if len(handshake_bytes) == self.handshake_message_length:
                    # We have the complete handshake bytes in our buffer, can
                    # parse now
                    handshake_struct = parse_handshake_struct(self.handshake_bytes)
                    self.handshake_bytes = b''
                    self.waiting_for_next_fragment = False
                    return handshake_struct
            else:
                self.handshake_bytes = b''
                handshake_message_type = fragment[0:1]
                self.handshake_message_length = fragment[1:5]
                handshake_body = fragment[5:]
                self.handshake_bytes += fragment
                if len(handshake_body) < struct.unpack("!I", self.handshake_message_length)[0]:
                    self.waiting_for_next_fragment = True
                else:
                    return self.handshake_bytes

