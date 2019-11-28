from pywallet.utils import HDPrivateKey, HDKey
from two1.bitcoin.utils import bytes_to_str

from service.api.ethereum.utils import normalize_key, ecsign
from service.settings import RELAY_ACCOUNT_PHRASE

master_key = HDPrivateKey.master_key_from_mnemonic(RELAY_ACCOUNT_PHRASE)
root_key = HDKey.from_path(master_key, "m/44'/60'/0'/0/0")
sender = root_key[-1].public_key.address()
signing_key = bytes_to_str(bytes(root_key[-1])[-32:])
normalized_key = normalize_key(signing_key)

def sign(hash):
    return ecsign(hash, normalized_key)