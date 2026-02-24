import hashlib

# insecure hashing (intentionally used for mypy plugin test coverage)
h = hashlib.md5(b"password").hexdigest()
print(h)
