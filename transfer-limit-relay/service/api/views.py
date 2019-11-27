from __future__ import division
import json
import string

import math
import requests
import rlp
import time
from pywallet.utils import HDPrivateKey, HDKey
from rest_framework.decorators import api_view
from rest_framework.response import Response
from two1.bitcoin.utils import bytes_to_str

from service import settings
from service.api.ethereum.authentication import get_sender
from service.api.ethereum.transactions import Transaction
from service.api.ethereum.utils import parse_int_or_hex, int_to_hex, parse_as_bin, is_numeric, sha3
from service.settings import RELAY_ACCOUNT_PHRASE, DEFAULT_GAS_PRICE, RPC_ENDPOINT, TRANSFER_LIMIT_MODULE, ALLOWANCE_LIMIT_MODULE

master_key = HDPrivateKey.master_key_from_mnemonic(RELAY_ACCOUNT_PHRASE)
root_key = HDKey.from_path(master_key, "m/44'/60'/0'/0/0")
sender = root_key[-1].public_key.address()


class RpcException(Exception):
    pass


def _request_headers():
    return {
        "Content-Type": "application/json; UTF-8",
    }


def rpc_call(method, params):
    data = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    return requests.post(RPC_ENDPOINT, data=json.dumps(data)).json()


def rpc_batch(calls):
    data = [{
        "id": index,
        "jsonrpc": "2.0",
        "method": call[0],
        "params": call[1]
    } for index, call in enumerate(calls) ]
    return requests.post(RPC_ENDPOINT, data=json.dumps(data)).json()


def rpc_result(method, param):
    return rpc_call(method, param)["result"]


def get_or_none(model, *args, **kwargs):
    # noinspection PyBroadException
    try:
        return model.objects.get(*args, **kwargs)
    except Exception:
        return None


def _build_get_limit_payload(account, token):
    return "0x484b8e96" + account[2:].zfill(64) + token[2:].zfill(64)


def _build_execute_transfer_limit_payload(account, token, to, amount, paymentToken, payment, signatures):
    return "0x7e7b6dbb" + \
        account[2:].zfill(64) + \
        token[2:].zfill(64) + \
        to[2:].zfill(64) + \
        int_to_hex(amount)[2:].zfill(64) + \
        paymentToken[2:].zfill(64) + \
        int_to_hex(payment)[2:].zfill(64) + \
        int_to_hex(224)[2:].zfill(64) + \
        int_to_hex(65)[2:].zfill(64) + \
        signatures[2:].zfill(96)


def _build_get_transfer_hash_payload(account, token, to, amount, paymentToken, payment, nonce):
    return "0xd626e043" + \
        account[2:].zfill(64) + \
        token[2:].zfill(64) + \
        to[2:].zfill(64) + \
        int_to_hex(amount)[2:].zfill(64) + \
        paymentToken[2:].zfill(64) + \
        int_to_hex(payment)[2:].zfill(64) + \
        int_to_hex(nonce)[2:].zfill(64)


def _get_nonce():
    return parse_int_or_hex(rpc_result("eth_getTransactionCount", [sender, "pending"]))


def _call(address, value=0, data=""):
    data = {
        "from": sender,
        "to": address,
        "value": "0x0" if value == 0 else int_to_hex(value),
        "data": data
    }
    response = rpc_call("eth_call", [data, "latest"])
    result = response.get("result")
    if not result:
        raise RpcException(response.get("error"))
    return result

def _estimate_transaction(address, value=0, data=""):
    data = {
        "from": sender,
        "to": address,
        "value": "0x0" if value == 0 else int_to_hex(value),
        "data": data
    }
    response = rpc_call("eth_estimateGas", [data])
    result = response.get("result")
    if not result:
        raise RpcException(response.get("error"))
    return parse_int_or_hex(result)


def _send_transaction(address, nonce, gas, gas_price=DEFAULT_GAS_PRICE, value=0, data=""):
    tx = Transaction(nonce, gas_price, gas, address, value, parse_as_bin(data)).sign(
        bytes_to_str(bytes(root_key[-1])[-32:]))
    response = rpc_call("eth_sendRawTransaction", ["0x" + bytes_to_str(rlp.encode(tx))])
    result = response.get("result")
    if not result:
        raise RpcException(response.get("error"))
    return result


def _validate_address(address):
    return not address or len(address) != 42 or not address.startswith("0x") or \
        not all(c in string.hexdigits for c in address[2:])


def _split_eth_data(eth_data):
    return [eth_data[part_start:part_start+64] for part_start in range(0, len(eth_data), 64)]


def _load_limit(safe, token):
    encoded_limit = _call(TRANSFER_LIMIT_MODULE, data=_build_get_limit_payload(safe, token))
    limit_array = _split_eth_data(encoded_limit[2:])
    return {
        "amount": parse_int_or_hex("0x" + limit_array[0]),
        "spend": parse_int_or_hex("0x" + limit_array[1]),
        "resetTimeMin": parse_int_or_hex("0x" + limit_array[2]),
        "lastTransferMin": parse_int_or_hex("0x" + limit_array[3]),
        "nonce": parse_int_or_hex("0x" + limit_array[4])
    }


@api_view(["GET"])
def get_limit(request, safe, token ):
    if _validate_address(safe):
        return Response({"error": "invalid safe address (format: <40 hex chars>)"}, 400)

    if _validate_address(token):
        return Response({"error": "invalid token address (format: <40 hex chars>)"}, 400)

    try:
        limit = _load_limit(safe, token)
    except RpcException as e:
        return Response({"error": "Could not fetch limit (%s)" % e}, 400)

    return Response(limit)


@api_view(["POST"])
def get_limit_transfer_hash(request, safe, token ):
    if _validate_address(safe):
        return Response({"error": "invalid safe address (format: <40 hex chars>)"}, 400)

    if _validate_address(token):
        return Response({"error": "invalid token address (format: <40 hex chars>)"}, 400)

    try:
        limit = _load_limit(safe, token)
    except RpcException as e:
        return Response({"error": "Could not fetch limit (%s)" % e}, 400)

    target = request.data.get("target")
    if _validate_address(target):
        return Response({"error": "invalid target address (format: <40 hex chars>)"}, 400)

    try:
        amount = parse_int_or_hex(request.data.get("amount"))
    except Exception:
        return Response({"error": "invalid amount provided (format: hex or decimal number)"}, 400)

    try:
        # account, token, to, amount, paymentToken, payment, nonce
        transferLimitHash = _call(TRANSFER_LIMIT_MODULE, data = _build_get_transfer_hash_payload(
            safe, token, target, amount, "0x0", 0, limit.get("nonce")
        ))
    except RpcException as e:
        return Response({"error": "Could get transfer limit hash (%s)" % e}, 400)

    # nonce = _get_nonce()
    return Response({"hash": transferLimitHash})


@api_view(["POST"])
def execute_limit_transfer(request, safe, token):
    if _validate_address(safe):
        return Response({"error": "invalid safe address (format: <40 hex chars>)"}, 400)

    if _validate_address(token):
        return Response({"error": "invalid token address (format: <40 hex chars>)"}, 400)

    try:
        limit = _load_limit(safe, token)
    except RpcException as e:
        return Response({"error": "Could not fetch limit (%s)" % e}, 400)

    target = request.data.get("target")
    if _validate_address(target):
        return Response({"error": "invalid target address (format: <40 hex chars>)"}, 400)

    try:
        amount = parse_int_or_hex(request.data.get("amount"))
    except Exception:
        return Response({"error": "invalid amount provided (format: hex or decimal number)"}, 400)

    try:
        signature = request.data["signature"]
    except Exception:
        return Response({"error": "invalid signature provided (format: hex-string)"}, 400)

    try:
        estimate = _estimate_transaction(TRANSFER_LIMIT_MODULE, data = _build_execute_transfer_limit_payload(
            safe, token, target, amount, "0x0", 0, signature
        ))
    except RpcException as e:
        return Response({"error": "Could not estimate transfer (%s)" % e}, 400)

    try:
        nonce = _get_nonce()
        tx_hash = _send_transaction(TRANSFER_LIMIT_MODULE, nonce, estimate, data = _build_execute_transfer_limit_payload(
            safe, token, target, amount, "0x0", 0, signature
        ))
    except RpcException as e:
        return Response({"error": "Could perform transfer (%s)" % e}, 400)

    return Response({"hash": tx_hash})


def _build_get_allowance_payload(account, delegate, token):
    return "0x94b31fbd" + account[2:].zfill(64) + delegate[2:].zfill(64) + token[2:].zfill(64)


def _build_execute_allowance_transfer_payload(account, token, to, amount, paymentToken, payment, delegate, signatures):
    return "0x4515641a" + \
        account[2:].zfill(64) + \
        token[2:].zfill(64) + \
        to[2:].zfill(64) + \
        int_to_hex(amount)[2:].zfill(64) + \
        paymentToken[2:].zfill(64) + \
        int_to_hex(payment)[2:].zfill(64) + \
        delegate[2:].zfill(64) + \
        int_to_hex(256)[2:].zfill(64) + \
        int_to_hex(65)[2:].zfill(64) + \
        signatures[2:].zfill(96)


def _load_allowance(safe, delegate, token):
    encoded_limit = _call(ALLOWANCE_LIMIT_MODULE, data=_build_get_allowance_payload(safe, delegate, token))
    limit_array = _split_eth_data(encoded_limit[2:])
    return {
        "amount": parse_int_or_hex("0x" + limit_array[0]),
        "spend": parse_int_or_hex("0x" + limit_array[1]),
        "resetTimeMin": parse_int_or_hex("0x" + limit_array[2]),
        "lastTransferMin": parse_int_or_hex("0x" + limit_array[3]),
        "nonce": parse_int_or_hex("0x" + limit_array[4])
    }


@api_view(["GET"])
def get_allowance(request, safe, delegate, token):
    if _validate_address(safe):
        return Response({"error": "invalid safe address (format: <40 hex chars>)"}, 400)

    if _validate_address(delegate):
        return Response({"error": "invalid delegate address (format: <40 hex chars>)"}, 400)

    if _validate_address(token):
        return Response({"error": "invalid token address (format: <40 hex chars>)"}, 400)

    try:
        allowance = _load_allowance(safe, delegate, token)
    except RpcException as e:
        return Response({"error": "Could not fetch allowance (%s)" % e}, 400)

    return Response(allowance)


@api_view(["POST"])
def submit_instant_transfer(request, safe, delegate, token):
    if _validate_address(safe):
        return Response({"error": "invalid safe address (format: <40 hex chars>)"}, 400)

    if _validate_address(delegate):
        return Response({"error": "invalid delegate address (format: <40 hex chars>)"}, 400)

    if _validate_address(token):
        return Response({"error": "invalid token address (format: <40 hex chars>)"}, 400)

    try:
        limit = _load_allowance(safe, delegate, token)
    except RpcException as e:
        return Response({"error": "Could not fetch allowance (%s)" % e}, 400)

    target = request.data.get("target")
    if _validate_address(target):
        return Response({"error": "invalid target address (format: <40 hex chars>)"}, 400)

    try:
        amount = parse_int_or_hex(request.data.get("amount"))
    except Exception:
        return Response({"error": "invalid amount provided (format: hex or decimal number)"}, 400)

    try:
        signature = request.data["signature"]
    except Exception:
        return Response({"error": "invalid signature provided (format: hex-string)"}, 400)

    try:
        estimate = _estimate_transaction(ALLOWANCE_LIMIT_MODULE, data = _build_execute_allowance_transfer_payload(
            safe, token, target, amount, "0x0", 0, delegate, signature
        ))
    except RpcException as e:
        return Response({"error": "Could not estimate transfer (%s)" % e}, 400)

    try:
        nonce = _get_nonce()
        tx_hash = _send_transaction(ALLOWANCE_LIMIT_MODULE, nonce, estimate, data = _build_execute_allowance_transfer_payload(
            safe, token, target, amount, "0x0", 0, delegate, signature
        ))
    except RpcException as e:
        return Response({"error": "Could perform transfer (%s)" % e}, 400)

    return Response({"hash": tx_hash})