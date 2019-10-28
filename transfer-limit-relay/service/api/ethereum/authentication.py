import binascii

from service.api.ethereum.utils import sha3, pubtoaddr, ecrecover_to_pub


def get_sender(account, signature):
    # noinspection PyBroadException
    try:
        return "0x" + binascii.hexlify(
            pubtoaddr(
                ecrecover_to_pub(sha3(binascii.unhexlify(account[2:])), binascii.unhexlify(signature))
            )
        ).lower().decode()
    except Exception as e:
        print(e)
        return None
