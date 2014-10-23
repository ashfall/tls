ECPoint = Struct(
    "public",
    UBInt8("length"),
    Bytes("point", lambda ctx: ctx.length),
)


ECParameters = Struct(
    "curve_params",
    UBInt8("curve_type"),
    Switch("data", lambda ctx: ctx.curve_type, {
        CurveType.NAMED_CURVE: UBInt16("namedcurve"),
    })
)


ServerECDHParams = Struct(
    "params",
    ECParameters,
    ECPoint,
)


Signature = Struct(
    "signed_params",
    Bytes("sha_hash", hashes.SHA1.digest_size)
)

# ServerKeyExchange for ECDH cipher suites
ServerKeyExchange = Struct(
    "ServerKeyExchange",
    ServerECDHParams,
    Signature,
)




class ECCurveType(Enum):
    EXPLICIT_PRIME = 1
    EXPLICIT_CHAR2 = 2
    NAMED_CURVE = 3


class NamedCurve(Enum):
    SECT163K1 = 1
    SECT163R1 = 2
    SECT163R2 = 3
    # ... fill me in when you're really bored...


@attributes(['params', 'signed_params'])
class ServerKeyExchange(object):
    pass


@attributes(['parameters', 'point'])
class ServerECDHParams(object):
    pass


@attributes(['curve_type', 'namedcurve'])
class ECParameters(object):
    pass


@attributes(['point'])
class ECPoint(object):
    pass


def parse_server_key_exchange(bytes):
    construct = _constructs.ServerKeyExchange.parse(bytes)
    return ServerKeyExchange(
        params=ServerECDHParams(
            parameters=ECParameters(
                curve_type=CurveType(construct.params.parameters.curve_type),
                namedcurve=NamedCurve(construct.params.parameters.data),
            ),
            point=ECPoint(construct.params.point),
        ),
        signed_params=construct.signed_params.sha_bytes,
    )
