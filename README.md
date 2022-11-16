# Proof Of Reserves
This project is a part of Pionex Proof of 100% Reserve.

# Verify your records in Merkle Tree

## Requirements
Python 3.4 or above

## Calculate Record ID
Record ID is a unique ID of your records in Merkle Tree. 
It is a hash value generated by the following content:
1. User ID: Unique ID of your Pionex account. This guarantees the record is only associated with your own account.
2. Proof ID: Unique ID of each Merkle Tree.
3. Nonce: Random bytes that prevent anyone from analyzing your snapshot with your User ID. Do not leak it to anyone else.

To calculate your record ID for Merkle Tree, please run the following script:
```shell
python main.py record-ID $proof_ID $user_ID $nonce
```

## Calculate Record Hash
The Hash of your assets is generated by following steps:
1. Generate your Record ID and input a "," after `$record_ID,`
2. Concat your assets with the format: `name:amount,name:amount` and add it after the record ID. Please note that the order of the assets must match the dictionary order of the assets names. eg: `$record_ID,ADA:123.2456,BTC:0.002412442,ETH:2.24123`
3. Concat total value in the end: `$record_ID,ADA:123.2456,BTC:0.002412442,ETH:2.24123,Total:1234.567`
4. Calculate sha256 for the content above, and then format it to a hex string.

The following script helps you to fulfill it:
```shell
python main.py hash $record_ID ADA:123.2456,BTC:0.002412442,ETH:2.24123,Total:1234.567
```

## Verify Merkle Tree
1. Generate the Hash of your data with the previous steps.
2. Get verification path from Pionex's Merkle Tree Verifier page.
3. Concat the path with the format: `index:hash`, eg: `7:5414ef4755d68c140831fa91b458e5eb2cbb40dbd99cca0b9515f37130763f12,2:17a1ab29cfff5ee16c946d6bfb74ac83cd7fa8c37b6a41dd94e6fabe52657aee`
4. Execute following script:
```shell
python main.py verify $hash 7:5414ef4755d68c140831fa91b458e5eb2cbb40dbd99cca0b9515f37130763f12,2:17a1ab29cfff5ee16c946d6bfb74ac83cd7fa8c37b6a41dd94e6fabe52657aee
```
5. Compare if the Merkle Tree Root Hash is the same as the published one.