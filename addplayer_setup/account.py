import secrets
import sha3
import eth_keys
from eth_keys import keys
from eth_account import Account, messages # This requires web3.py installed

with open("account_creation.sh", "a") as f1, open("fund_transfer.sh", "a") as f2, open("unlock_account.sh", "a") as f3, open("parameters.txt", "a") as f4, open("all_parameters.txt", "a") as f5:
    for i in range(100):
        # Code for creation of account using private key 

        private_key = str(hex(secrets.randbits(256))[2:])
        if len(private_key) != 64:
            private_key = private_key.zfill(64)
        try:
            private_key_bytes = bytes.fromhex(private_key)
        except:
            i = i - 1
        public_key_hex = keys.PrivateKey(private_key_bytes).public_key
        try:
            public_key_bytes = bytes.fromhex(str(public_key_hex)[2:])
        except:
            i = i - 1
        Keccak256_of_public_key_bytes = sha3.keccak_256(public_key_bytes).hexdigest()
        public_address = keys.PublicKey(public_key_bytes).to_address()

        keccak256_hash = sha3.keccak_256(public_address.encode('utf-8')).hexdigest()
        message = messages.encode_defunct(hexstr=keccak256_hash)
        signed_message = Account.sign_message(message, private_key=private_key)

        f1.write('geth attach --exec \'web3.personal.importRawKey("' + private_key + '","");\'\n')

        # Code for fund transfer (100 Ethers each) from the coinbase account
        f2.write('geth attach --exec \'eth.sendTransaction({from: "0xc0A8e4D217eB85b812aeb1226fAb6F588943C2C2",to: "' + public_address + '", value: "100000000000000000000"});\'\n')

        # Code for permanent account unlocking
        f3.write('geth attach --exec \'web3.personal.unlockAccount("' + public_address + '", "", 0);\'\n')

        # Code for parameters
        if i == 99:
            f4.write('"' + public_address + '", "0x' + keccak256_hash + '", "' + signed_message.signature.hex() + '"];') 
        elif i == 0:
            f4.write('const parameters = ["' + public_address + '", "0x' + keccak256_hash + '", "' + signed_message.signature.hex() + '", ') 
        else:
            f4.write('"' + public_address + '", "0x' + keccak256_hash + '", "' + signed_message.signature.hex() + '", ') 

        # Code for saving all paramters
        f5.write('"' + public_address + '", "' + private_key + '", "' + keccak256_hash + '", "' + signed_message.signature.hex() + '"\n')

f1.close()
f2.close()
f3.close()
f4.close()
f5.close()
