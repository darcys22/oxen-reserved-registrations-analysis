import argparse
import json
import requests
import time
import signal
import sys
from tx_extra_parser import parse_tx_extra

# Configuration
class Config:
    listen_ip = "public-eu.optf.ngo"
    listen_port = "22023"

config = Config()

# Global flag for graceful exit
exit_flag = False

def signal_handler(signum, frame):
    global exit_flag
    print("\nCtrl+C received. Exiting gracefully...")
    exit_flag = True

def instruct_daemon(method, params):
    payload = json.dumps({"method": method, "params": params}, skipkeys=False)
    headers = {'content-type': "application/json"}
    try:
        response = requests.request("POST", f"http://{config.listen_ip}:{config.listen_port}/json_rpc", data=payload, headers=headers)
        return json.loads(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}")
    except:
        print('No response from daemon, check daemon is running on this machine')
    return None

def get_latest_height():
    response = instruct_daemon('getheight', {})
    if response and 'result' in response:
        return response['result']['height']
    return None

def get_block(height):
    params = {"height": height, "decode_as_json": True}
    return instruct_daemon('get_block', params)

def get_transaction(tx_hash):
    params = {"txs_hashes": [tx_hash], "decode_as_json": True}
    return instruct_daemon('get_transactions', params)

def process_blocks(start_height, end_height):
    global exit_flag
    for height in range(start_height, end_height - 1, -1):
        if exit_flag:
            print("Exiting block processing...")
            break
        print(f"Processing block at height: {height}")
        block_data = get_block(height)
        if block_data and 'result' in block_data and 'tx_hashes' in block_data['result']:
            tx_hashes = block_data['result']['tx_hashes']
            for tx_hash in tx_hashes:
                if exit_flag:
                    break
                try:
                    process_transaction(height, tx_hash)
                except:
                    print("Transaction at {} failed to process:".format(height))
        time.sleep(0.01)  # Add a small delay to avoid overwhelming the daemon


def process_transaction(height, tx_hash):
    tx_data = get_transaction(tx_hash)
    if tx_data and 'result' in tx_data and 'txs' in tx_data['result'] and tx_data['result']['txs']:
        tx_extra_hex_arr = json.loads(tx_data['result']['txs'][0]['as_json'])['extra']
        tx_extra_hex = ''.join([hex(x)[2:].zfill(2) for x in tx_extra_hex_arr])
        if tx_extra_hex:
            parsed_tx_extra = parse_tx_extra(tx_extra_hex)
            for item in parsed_tx_extra:
                if 'TX_EXTRA_TAG_SERVICE_NODE_REGISTER' in item:
                    spend_pubkeys_count = len(item['TX_EXTRA_TAG_SERVICE_NODE_REGISTER']['spend_pubkeys'])
                    with open('output.txt', 'a') as f:
                        f.write(f"{height},{spend_pubkeys_count}\n")
                    break

def main():
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(description='Process blocks and transactions')
    parser.add_argument("--start", type=int, help="Start height (default: latest height)")
    parser.add_argument("--end", type=int, help="End height (default: 0)")
    parser.add_argument("--limit", type=int, help="Limit the number of blocks to process")
    args = parser.parse_args()

    latest_height = get_latest_height()
    if latest_height is None:
        print("Failed to get the latest height. Exiting.")
        return

    start_height = args.start if args.start is not None else latest_height - 1
    end_height = args.end if args.end is not None else 0

    if args.limit:
        end_height = max(end_height, start_height - args.limit)

    print(f"Processing blocks from height {start_height} to {end_height}")
    process_blocks(start_height, end_height)

    if exit_flag:
        print("Script execution interrupted by user.")
    else:
        print("Script execution completed.")

if __name__ == "__main__":
    main()
