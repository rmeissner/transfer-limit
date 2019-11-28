from __future__ import division

import string

from rest_framework.decorators import api_view
from rest_framework.response import Response

from service.api.ethereum.utils import parse_int_or_hex, int_to_hex
from service.api.services.contracts import call
from service.api.services.eoa import sender, _estimate_transaction_eoa, _send_transaction_eoa
from service.api.services.rpc import RpcException, rpc_call
from service.api.services.safe import _estimate_transaction_safe, _send_transaction_safe
from service.settings import TRANSFER_LIMIT_MODULE, ALLOWANCE_LIMIT_MODULE, RELAY_SAFE_ADDRESS


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


def _estimate_transaction(address, value=0, data="0x"):
    if RELAY_SAFE_ADDRESS:
        return _estimate_transaction_safe(address, value, data)
    else:
        return _estimate_transaction_eoa(address, value, data)


def _send_transaction(address, params, value=0, data="0x"):
    if RELAY_SAFE_ADDRESS:
        return _send_transaction_safe(address, params, value, data)
    else:
        return _send_transaction_eoa(address, params, value, data)


def _validate_address(address):
    return not address or len(address) != 42 or not address.startswith("0x") or \
        not all(c in string.hexdigits for c in address[2:])


def _split_eth_data(eth_data):
    return [eth_data[part_start:part_start+64] for part_start in range(0, len(eth_data), 64)]


def _load_limit(safe, token):
    encoded_limit = call(TRANSFER_LIMIT_MODULE, data=_build_get_limit_payload(safe, token))
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
        transferLimitHash = call(TRANSFER_LIMIT_MODULE, data = _build_get_transfer_hash_payload(
            safe, token, target, amount, "0x0", 0, limit.get("nonce")
        ))
    except RpcException as e:
        return Response({"error": "Could get transfer limit hash (%s)" % e}, 400)

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
        params = _estimate_transaction(TRANSFER_LIMIT_MODULE, data = _build_execute_transfer_limit_payload(
            safe, token, target, amount, "0x0", 0, signature
        ))
    except RpcException as e:
        return Response({"error": "Could not estimate transfer (%s)" % e}, 400)

    try:
        tx_hash = _send_transaction(TRANSFER_LIMIT_MODULE, params, data = _build_execute_transfer_limit_payload(
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
    encoded_limit = call(ALLOWANCE_LIMIT_MODULE, data=_build_get_allowance_payload(safe, delegate, token))
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

    execution_payload = _build_execute_allowance_transfer_payload(
        safe, token, target, amount, "0x0", 0, delegate, signature
    )
    try:
        params = _estimate_transaction(ALLOWANCE_LIMIT_MODULE, data = execution_payload)
    except RpcException as e:
        return Response({"error": "Could not estimate transfer with %s (%s)" % (execution_payload, e)}, 400)

    try:
        tx_hash = _send_transaction(ALLOWANCE_LIMIT_MODULE, params, data = execution_payload)
    except RpcException as e:
        return Response({"error": "Could perform transfer with %s (%s)" % (execution_payload, e)}, 400)

    return Response({"hash": tx_hash})