import hmac
import argparse
from hashlib import sha256


def calculate_record_id(proof_id, user_id, nonce):
    record_id = hmac.new(nonce.encode(), f'{proof_id},{user_id}'.encode(), digestmod="SHA256").hexdigest()
    return record_id


parser = argparse.ArgumentParser(description="Pionex Proof of Reserves Verification Tool")
subparsers = parser.add_subparsers(title='commands', help='all valid commands', dest='command')

record_id_parser = subparsers.add_parser('record-id', help='calculate record id.')
record_id_parser.add_argument('proofId', help='The unique id for each Merkle Tree.')
record_id_parser.add_argument('userId', help='The unique id for each User.')
record_id_parser.add_argument('nonce', help='A sequence of secret bytes used to protect personal privacy. Don\'t leak it to anybody.')

hash_parser = subparsers.add_parser('hash', help='Calculate hash for your assets.')
hash_parser.add_argument('recordId', help='The unique id for your record in the MerkleTree.')
hash_parser.add_argument('assets', help='Concat your assets with the format: "ADA:123.456,ETH:0.0234,Total:123.456"')

verify_parser = subparsers.add_parser('verify', help='Verify your record in Merkle Tree.')
verify_parser.add_argument('hash', help='Hash of your record in the MerkleTree.')
verify_parser.add_argument('treePath', help='Concat the path in Merkle Tree with the format: "3354149:a0441784836cc6b1c78d1726c913fe037b577e2f7a863693f5ea68e3c8de94a5,1677075:f7d09437607b787e92783e5ca4fcabacafd0d64a51fa3e55d57b15c74af581b0"')
verify_parser.add_argument('-r', '--root', help='Root of Merkle Tree')

args = parser.parse_args()

if args.command == "record-id":
    print(calculate_record_id(args.proofId, args.userId, args.nonce))
elif args.command == "hash":
    assets = args.assets
    assets_components = assets.split(',')
    assets_dict = dict(tuple(a.split(':')) for a in assets_components)
    total = assets_dict.pop('Total')
    if not total:
        print("Total value is missing")
        exit(-1)
    sorted_keys = sorted(assets_dict.keys())
    assets_str = f'{args.recordId},' + ','.join([f'{k}:{assets_dict[k]}' for k in sorted_keys]) + f',Total:{total}'
    print(sha256(assets_str.encode()).hexdigest())
elif args.command == "verify":
    path = args.treePath
    path_components = path.split(',')
    path_dict = dict(tuple(a.split(':')) for a in path_components)
    sorted_keys = sorted([int(k) for k in path_dict.keys()], reverse=True)
    hash_bytes = bytes.fromhex(args.hash)
    for k in sorted_keys:
        if k % 2 == 1:
            hash_bytes = sha256(hash_bytes + bytes.fromhex(path_dict[str(k)])).digest()
        else:
            hash_bytes = sha256(bytes.fromhex(path_dict[str(k)]) + hash_bytes).digest()

    root_hex = hash_bytes.hex()
    print('root hash: ')
    print(root_hex)

    if args.root:
        if args.root == root_hex:
            print('Verified!')
        else:
            print("Failed!")
    else:
        print('Compare it with the root of the Merkle Tree')
