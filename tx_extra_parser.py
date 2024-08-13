#!/usr/bin/python3

import argparse
from enum import IntFlag, auto

tag_dictionary = {
    "00": "TX_EXTRA_TAG_PADDING",
    "01": "TX_EXTRA_TAG_PUBKEY",
    "02": "TX_EXTRA_NONCE",
    "03": "TX_EXTRA_MERGE_MINING_TAG",
    "04": "TX_EXTRA_TAG_ADDITIONAL_PUBKEYS",
    "70": "TX_EXTRA_TAG_SERVICE_NODE_REGISTER",
    "71": "TX_EXTRA_TAG_SERVICE_NODE_DEREG_OLD",
    "72": "TX_EXTRA_TAG_SERVICE_NODE_WINNER",
    "73": "TX_EXTRA_TAG_SERVICE_NODE_CONTRIBUTOR",
    "74": "TX_EXTRA_TAG_SERVICE_NODE_PUBKEY",
    "75": "TX_EXTRA_TAG_TX_SECRET_KEY",
    "76": "TX_EXTRA_TAG_TX_KEY_IMAGE_PROOFS",
    "77": "TX_EXTRA_TAG_TX_KEY_IMAGE_UNLOCK",
    "78": "TX_EXTRA_TAG_SERVICE_NODE_STATE_CHANGE",
    "79": "TX_EXTRA_TAG_BURN",
    "7A": "TX_EXTRA_TAG_OXEN_NAME_SYSTEM"
}

nonce_tag_dictionary = {
    "00": "payment_id",
    "01": "encrypted_payment_id"
}

ons_type_dictionary = {
    "00": "session",
    "01": "wallet",
    "02": "lokinet",
    "03": "lokinet 2 year",
    "04": "lokinet 5 year",
    "05": "lokinet 10 year"
}

class ONS_EXTRA_FIELD(IntFlag):
    OWNER = auto()
    BACKUP_OWNER = auto()
    SIGNATURE = auto()
    ENCRYPTED_VALUE = auto()

class ONS_Extra_Field_Set:
    def __init__(self, *flags):
        self._extras = ONS_EXTRA_FIELD(0)
        for flag in flags:
            self._extras |= ONS_EXTRA_FIELD[flag.upper()]
    def __contains__(self, item):
        return (self._extras & item) == item

def eat_pubkey_data(tx_extra_list):
    pubkey = ''.join(tx_extra_list[:64])
    return {"pubkey": pubkey}, tx_extra_list[64:]

def eat_nonce_data(tx_extra_list):
    size = (int(''.join(tx_extra_list[:2])) - 1) * 2
    nonce_tag = ''.join(tx_extra_list[2:4])
    nonce_data = ''.join(tx_extra_list[4:4+size])
    return {nonce_tag_dictionary[nonce_tag]: nonce_data}, tx_extra_list[4+size:]

def eat_ons_generic_owner(tx_extra_list):
    owner_type = ''.join(tx_extra_list[:2])
    spend_public_key = ''.join(tx_extra_list[2:66])
    view_public_key = ''.join(tx_extra_list[66:130])
    is_subaddress = ''.join(tx_extra_list[130:132])
    return {"type": owner_type,
            "spend_public_key": spend_public_key,
            "view_public_key": view_public_key,
            "is_subaddress": is_subaddress}, tx_extra_list[132:]

def eat_ons_data(tx_extra_list):
    version = ''.join(tx_extra_list[:2])
    ons_type = ''.join(tx_extra_list[2:4])
    name_hash = ''.join(tx_extra_list[4:68])
    prev_txid = ''.join(tx_extra_list[68:132])
    ons_fields = ONS_EXTRA_FIELD(int(''.join(tx_extra_list[132:134])))
    ons_data = {'version': version,
                'type': ons_type_dictionary[ons_type],
                'name_hash': name_hash,
                'prev_txid': prev_txid,
                'fields': ons_fields}
    tx_extra_list = tx_extra_list[134:]
    ons_extra_field_set = ONS_Extra_Field_Set()
    ons_extra_field_set._extras = ons_fields
    if ONS_EXTRA_FIELD.OWNER in ons_extra_field_set:
        ons_data['owner'], tx_extra_list = eat_ons_generic_owner(tx_extra_list)
    if ONS_EXTRA_FIELD.BACKUP_OWNER in ons_extra_field_set:
        ons_data['backup_owner'], tx_extra_list = eat_ons_generic_owner(tx_extra_list)
    if ONS_EXTRA_FIELD.SIGNATURE in ons_extra_field_set:
        ons_data['signature'] = ''.join(tx_extra_list[:64])
        tx_extra_list = tx_extra_list[64:]
    if ONS_EXTRA_FIELD.ENCRYPTED_VALUE in ons_extra_field_set:
        size = int(''.join(tx_extra_list[:2]), 16) * 2
        ons_data['encrypted_value'] = ''.join(tx_extra_list[2:2+size])
        tx_extra_list = tx_extra_list[2+size:]
    return ons_data, tx_extra_list

def eat_uint64_t(tx_extra_list):
    amount = ''.join(tx_extra_list[:16])
    return int.from_bytes(bytearray.fromhex(amount), "little", signed=False), tx_extra_list[16:]

def eat_burn(tx_extra_list):
    amount, tx_extra_list = eat_uint64_t(tx_extra_list)
    return {"amount": amount}, tx_extra_list

def eat_register_data(tx_extra_list):
    register_data = {}
    spend_pubkey_size = (int(''.join(tx_extra_list[:2])))
    tx_extra_list = tx_extra_list[2:]
    register_data["spend_pubkeys"] = []
    for i in range(spend_pubkey_size):
        register_data["spend_pubkeys"].append(''.join(tx_extra_list[:64]))
        tx_extra_list = tx_extra_list[64:]
    view_pubkey_size = (int(''.join(tx_extra_list[:2])))
    tx_extra_list = tx_extra_list[2:]
    register_data["view_pubkeys"] = []
    for i in range(view_pubkey_size):
        register_data["view_pubkeys"].append(''.join(tx_extra_list[:64]))
        tx_extra_list = tx_extra_list[64:]
    register_data["fee"], tx_extra_list = eat_uint64_t(tx_extra_list)
    register_data["amounts"] = []
    for i in range(view_pubkey_size):
        amount, tx_extra_list = eat_uint64_t(tx_extra_list)
        register_data["amounts"].append(amount)
    register_data["hf_or_expiration"], tx_extra_list = eat_uint64_t(tx_extra_list)
    register_data['signature'] = ''.join(tx_extra_list[:64])
    tx_extra_list = tx_extra_list[64:]
    return register_data, tx_extra_list

eat_data_functions = {
    "TX_EXTRA_TAG_PUBKEY": eat_pubkey_data,
    "TX_EXTRA_NONCE": eat_nonce_data,
    "TX_EXTRA_TAG_OXEN_NAME_SYSTEM": eat_ons_data,
    "TX_EXTRA_TAG_BURN": eat_burn,
    "TX_EXTRA_TAG_SERVICE_NODE_REGISTER": eat_register_data
}

def parse_tx_extra(tx_extra):
    tx_extra_list = list(tx_extra)
    result = []
    while len(tx_extra_list) > 0:
        tag = ''.join(tx_extra_list[:2]).upper()
        if tag not in tag_dictionary:
            break
        tag_string = tag_dictionary[tag]
        print(tag_string)
        tx_extra_list = tx_extra_list[2:]
        if tag_string in eat_data_functions:
            data, tx_extra_list = eat_data_functions[tag_string](tx_extra_list)
            result.append({tag_string: data})
        else:
            result.append({tag_string: None})
            break
    return result

def main():
    parser = argparse.ArgumentParser(description='Decode TX Extra')
    parser.add_argument("--tx-extra", required=True, help="Hex string for the tx extra to be decoded, type=string")
    args = parser.parse_args()

    result = parse_tx_extra(args.tx_extra)
    for item in result:
        print(item)

if __name__ == "__main__":
    main()
