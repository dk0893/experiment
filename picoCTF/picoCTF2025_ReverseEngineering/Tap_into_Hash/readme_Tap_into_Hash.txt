1つの暗号化されたファイル（enc_flag）と、Pythonスクリプト（block_chain.py）がダウンロードできます。

<figure class="figure-image figure-image-fotolife" title="Tap into Hash（200 points）">[f:id:daisuke20240310:20250310213033p:plain:alt=Tap into Hash（200 points）]<figcaption>Tap into Hash（200 points）</figcaption></figure>

暗号化ファイルはテキストファイルでした。

```
Key: b'\xa9\xcco`\xfa\xf9\xb5\xc0\xda\xf6*\xb3\xbe\xa9t\x0fi\xae\x13\x01q-\xae\x9ap\xb7\xa45\x1e{\xaa\xb4'
Encrypted Blockchain: b'\xf7Y\x8db\x8bS\xb2\x80q\xf2\xa0\x87\xd6(\xfc\xe6\xf2\\\x82`\x8c\\\xb4\xd4v\xf0\xf2\xd1\xde/\xfa\xb0\xfb]\xdfg\x8bV\xe2\xd1$\xa5\xa6\xd9\x8c+\xa8\xe7\xa6X\x82d\xda\x01\xb1\x85u\xa4\xa3\xd3\xda}\xff\xbc\xeeZ\x8am\x8d\x01\xb1\x84$\xa1\xf4\x85\x8c,\xfa\xe7\xf0S\x8f4\x8f\x02\xb1\x82w\xf1\xf6\x85\xd7/\xff\xb3\xa6]\xdf`\x8b\x00\xe3\xd1"\xf2\xf6\xd8\xda|\xfd\xb7\xf3Z\xd83\xdc\\\xbe\xd6!\xa2\xae\xd8\x8c{\xfa\xb0\xf2G\x8ae\x8a\x01\xe3\xd7q\xf4\xa3\xd9\x8aq\xfd\xbd\xfb\x08\x8ag\x8dQ\xe3\xd0"\xa4\xf2\x84\xdeq\xac\xb5\xf4\x0e\xca<\xdd\x0b\xc5\xe6U\xbc\xf5\x8d\x81*\xa6\xdb\xf09\xe8=\xe8\r\xd4\xd0G\xf6\xe6\x82\xb6\x16\x95\xd1\xa9\'\x8a\'\x8a]\xe5\xfaL\xb6\xd4\x9b\x83\x03\x97\xfe\x81!\xe5a\x87\\\xbf\xd4*\xa2\xf6\x9c\xdex\xf4\xe5\xf6R\x8em\x87W\xb1\x80 \xf5\xf4\xd6\x8a{\xfd\xe7\xf3\x08\x89d\xdfP\xb2\x82u\xf4\xa0\x80\xc3y\xfd\xb2\xa5[\x83m\x8dQ\xe5\x84+\xfe\xa5\x84\xd7p\xf4\xb6\xf1S\x89m\xddQ\xb0\xd7&\xf2\xf2\xd3\x8b,\xf9\xb5\xfa\x08\xd8f\x8c\\\xe5\xd7"\xf3\xf6\xd4\x8c|\xac\xe5\xa7\x08\x8ag\x8d\x02\xbe\xd1$\xa2\xa3\x80\x8ad\xfd\xb4\xa6]\xdc0\xd8W\xb1\x85q\xa5\xf6\x80\xdbq\xa9\xb5\xf0_\xdee\x8e\x00\xbe\xd3r\xf4\xa2\xd4\x88y\xf4\xb0\xa5_\xdc4\xda\x05\xb7\x80r\xf1\xa3\x84\x8ap\xfb\xb2\xfa\x08\x8c`\x8eR\xe3\x81q\xfe\xae\x84\x88x\xcf\x86'
```

Pythonスクリプトは以下です。VSCode でデバッグしながら見ていきます。

コマンドライン引数が必要なので、適当な文字列（"aaa"）を入力して進めていきます。ざっと見ましたが、だいぶ難しいです。

```python
import time
import base64
import hashlib
import sys
import secrets


class Block:
    def __init__(self, index, previous_hash, timestamp, encoded_transactions, nonce):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.encoded_transactions = encoded_transactions
        self.nonce = nonce

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.encoded_transactions}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()


def proof_of_work(previous_block, encoded_transactions):
    index = previous_block.index + 1
    timestamp = int(time.time())
    nonce = 0

    block = Block(index, previous_block.calculate_hash(),
                  timestamp, encoded_transactions, nonce)

    while not is_valid_proof(block):
        nonce += 1
        block.nonce = nonce

    return block


def is_valid_proof(block):
    guess_hash = block.calculate_hash()
    return guess_hash[:2] == "00"


def decode_transactions(encoded_transactions):
    return base64.b64decode(encoded_transactions).decode('utf-8')


def get_all_blocks(blockchain):
    return blockchain


def blockchain_to_string(blockchain):
    block_strings = [f"{block.calculate_hash()}" for block in blockchain]
    return '-'.join(block_strings)


def encrypt(plaintext, inner_txt, key):
    midpoint = len(plaintext) // 2

    first_part = plaintext[:midpoint]
    second_part = plaintext[midpoint:]
    modified_plaintext = first_part + inner_txt + second_part
    block_size = 16
    plaintext = pad(modified_plaintext, block_size)
    key_hash = hashlib.sha256(key).digest()

    ciphertext = b''

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        cipher_block = xor_bytes(block, key_hash)
        ciphertext += cipher_block

    return ciphertext


def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data.encode() + padding


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def generate_random_string(length):
    return secrets.token_hex(length // 2)


random_string = generate_random_string(64)


def main(token):
    key = bytes.fromhex(random_string)

    print("Key:", key)

    genesis_block = Block(0, "0", int(time.time()), "EncodedGenesisBlock", 0)
    blockchain = [genesis_block]

    for i in range(1, 5):
        encoded_transactions = base64.b64encode(
            f"Transaction_{i}".encode()).decode('utf-8')
        new_block = proof_of_work(blockchain[-1], encoded_transactions)
        blockchain.append(new_block)

    all_blocks = get_all_blocks(blockchain)

    blockchain_string = blockchain_to_string(all_blocks)
    encrypted_blockchain = encrypt(blockchain_string, token, key)

    print("Encrypted Blockchain:", encrypted_blockchain)


if __name__ == "__main__":
    text = sys.argv[1]
    main(text)
```

encrypt関数がポイントな気がします。encrypt関数の引数は、そこまでに作った 5個のブロックを `-` で繋いだ文字列と、コマンドライン引数で指定した文字列と、ランダムな文字列です。

encrypt関数を詳細に見ます。midpoint は、常に 162 になるようです。plaintext（324文字）を、前半分を first_part に入れて、後半分を second_part に入れます。コマンドライン引数で指定した文字列を真ん中に入れて、これらを連結します。パディングして 16の倍数にします。ランダムな文字列を使って、sha256 で、32byte のダイジェストを作ります。for文では、16byteずつ取り出して、ダイジェストと XOR を取ったものを ciphertext として連結します。

これ以上、遡っていくのは難しいので、まずは、これを逆算するような Pythonスクリプトを作っていきます。

```python
import hashlib
import sys

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

key = b'\xa9\xcco`\xfa\xf9\xb5\xc0\xda\xf6*\xb3\xbe\xa9t\x0fi\xae\x13\x01q-\xae\x9ap\xb7\xa45\x1e{\xaa\xb4'
ciphertext = b'\xf7Y\x8db\x8bS\xb2\x80q\xf2\xa0\x87\xd6(\xfc\xe6\xf2\\\x82`\x8c\\\xb4\xd4v\xf0\xf2\xd1\xde/\xfa\xb0\xfb]\xdfg\x8bV\xe2\xd1$\xa5\xa6\xd9\x8c+\xa8\xe7\xa6X\x82d\xda\x01\xb1\x85u\xa4\xa3\xd3\xda}\xff\xbc\xeeZ\x8am\x8d\x01\xb1\x84$\xa1\xf4\x85\x8c,\xfa\xe7\xf0S\x8f4\x8f\x02\xb1\x82w\xf1\xf6\x85\xd7/\xff\xb3\xa6]\xdf`\x8b\x00\xe3\xd1"\xf2\xf6\xd8\xda|\xfd\xb7\xf3Z\xd83\xdc\\\xbe\xd6!\xa2\xae\xd8\x8c{\xfa\xb0\xf2G\x8ae\x8a\x01\xe3\xd7q\xf4\xa3\xd9\x8aq\xfd\xbd\xfb\x08\x8ag\x8dQ\xe3\xd0"\xa4\xf2\x84\xdeq\xac\xb5\xf4\x0e\xca<\xdd\x0b\xc5\xe6U\xbc\xf5\x8d\x81*\xa6\xdb\xf09\xe8=\xe8\r\xd4\xd0G\xf6\xe6\x82\xb6\x16\x95\xd1\xa9\'\x8a\'\x8a]\xe5\xfaL\xb6\xd4\x9b\x83\x03\x97\xfe\x81!\xe5a\x87\\\xbf\xd4*\xa2\xf6\x9c\xdex\xf4\xe5\xf6R\x8em\x87W\xb1\x80 \xf5\xf4\xd6\x8a{\xfd\xe7\xf3\x08\x89d\xdfP\xb2\x82u\xf4\xa0\x80\xc3y\xfd\xb2\xa5[\x83m\x8dQ\xe5\x84+\xfe\xa5\x84\xd7p\xf4\xb6\xf1S\x89m\xddQ\xb0\xd7&\xf2\xf2\xd3\x8b,\xf9\xb5\xfa\x08\xd8f\x8c\\\xe5\xd7"\xf3\xf6\xd4\x8c|\xac\xe5\xa7\x08\x8ag\x8d\x02\xbe\xd1$\xa2\xa3\x80\x8ad\xfd\xb4\xa6]\xdc0\xd8W\xb1\x85q\xa5\xf6\x80\xdbq\xa9\xb5\xf0_\xdee\x8e\x00\xbe\xd3r\xf4\xa2\xd4\x88y\xf4\xb0\xa5_\xdc4\xda\x05\xb7\x80r\xf1\xa3\x84\x8ap\xfb\xb2\xfa\x08\x8c`\x8eR\xe3\x81q\xfe\xae\x84\x88x\xcf\x86'

print( f"len(key)={len(key)}, len(ciphertext)={len(ciphertext)}" ) # 32 384 (162 + 60 + 162)

key_hash = hashlib.sha256(key).digest()
print( f"key_hash={key_hash}, len(key_hash)={len(key_hash)}" )

block_size = 16
plaintext = b''

for i in range(0, len(ciphertext), block_size):
    block = ciphertext[i:i + block_size]
    plain_block = xor_bytes(block, key_hash)
    plaintext += plain_block

print( f"plaintext={plaintext}" )
```

とりあえず、実行してみます。

plaintext の途中にフラグのようなものが見えます。これを提出するとクリアでした。

```sh
$ python block_chain_decode.py
len(key)=32, len(ciphertext)=384
key_hash=b'\xc3j\xbaU\xbed\x86\xb2\x13\xc7\x97\xe1\xeeI\xcd\x84\xdb\xfb\xaf2\x10k>\x8b\xb3\xfe\xcb3`a\xaa\x82', len(key_hash)=32
plaintext=b'43775742b57f8a1b1685282fe7e00f7487e252dc7b18bbece281de77fc424428-0083e767fcdbe7c395a1f70d6ad9f27e7e55dec15a9450300bfb88d2e99b2741-004eeeb348d8098b0235eb1cee08a17dpicoCTF{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_4989f9ea}019a5848937232c7d20c0b31a440f37a-006f19835c6892e99922938c56e55e2ee419bb328ce14a5b5aadb023f8c7e4ad-00e7fef377bbaa58d135d00d8aa355f094f5fada12a64ed9669b6506e3b99ef1\x02\x02'
```
