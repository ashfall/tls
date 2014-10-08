import struct

from tls.record import ContentType

HANDSHAKE_MESSAGE_LENGTH_START_INDEX = 1
HANDSHAKE_BODY_START_INDEX = 5


class HandshakeBuffer(object):
    def __init__(self, callback_with_handshake_bytes,
                 errback_for_insufficient_info):
        self.handshake_bytes = b''
        self.waiting_for_next_fragment = False
        self.callback_with_handshake_bytes = callback_with_handshake_bytes
        self.errback_for_insufficient_info = errback_for_insufficient_info

    def buffer_handshake_if_fragmented(self, tls_plaintext):
        type = tls_plaintext.type
        fragment = tls_plaintext.fragment

        if type == ContentType.HANDSHAKE and fragment:
            if self.waiting_for_next_fragment:
                self.handshake_bytes += fragment
                if len(self.handshake_bytes[HANDSHAKE_BODY_START_INDEX:]) == \
                        struct.unpack("!I", self.handshake_message_length)[0]:
                    # We have the complete handshake bytes in our buffer, can
                    # parse now
                    self.waiting_for_next_fragment = False
                    self.callback_with_handshake_bytes(self.handshake_bytes)
                    self.handshake_bytes = b''
            else:
                if len(fragment) < HANDSHAKE_BODY_START_INDEX:
                    self.errback_for_insufficient_info()
                    return None

                self.handshake_bytes = b''
                self.handshake_message_length = fragment[
                    HANDSHAKE_MESSAGE_LENGTH_START_INDEX:
                    HANDSHAKE_BODY_START_INDEX
                ]
                handshake_body = fragment[HANDSHAKE_BODY_START_INDEX:]
                self.handshake_bytes += fragment
                if len(handshake_body) < struct.unpack(
                    "!I",
                    self.handshake_message_length
                )[0]:
                    self.waiting_for_next_fragment = True
                else:
                    self.callback_with_handshake_bytes(self.handshake_bytes)
        else:
            pass
            # TODO: Figure out buffering when the message being carried is not
            # a Handshake struct.
