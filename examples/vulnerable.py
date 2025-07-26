import hashlib
from Crypto.Cipher import AES

# insecure hashing
h = hashlib.md5(b"password").hexdigest()

# insecure AES usage
cipher = AES.new(b"0" * 16, mode=AES.MODE_ECB)
ct = cipher.encrypt(b"secret data")
