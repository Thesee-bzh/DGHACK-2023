from pwn import xor
from base64 import b64decode

# AES-128 CTR
# key = 128bits / 16bytes
# block-size = 16 bytes (always in AES)
# nonce = 8bytes, counter = 8bytes
BLOCK_SIZE = 16

# Plaintext that supposedly was used to encode msg2 ???
# Take care of PKCS7 padding: padding value = number of padding bytes to add
pt2  = "Build with love, kitties and flowers".encode()
pad  = BLOCK_SIZE - (len(pt2) % BLOCK_SIZE)
pt2 += chr(pad).encode() * pad
#print(pt2)
#b'Build with love, kitties and flowers\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'

# encrypted
b64_msg1 = '34aff6de8f8c01b25c56c52261e49cbddQsBGjy+uKhZ7z3+zPhswKWQHMYJpz7wffAe4Es/bwrJmMo99Kv7XJ8P63TbN/8X'
msg1 = b64decode(b64_msg1)

b64_msg2 = '34aff6de8f8c01b25c56c52261e49cbdC19FW3jqqqxd6G/z0fcpnOSIBsUSvD+jZ7E9/VkscwDMrdk9i9efIvJw1Fj6Fs0R'
msg2 = b64decode(b64_msg2)

# Extract Keystream
keystream = xor(msg1[:len(msg2)], msg2)

# Decode msg1
pt1 = xor(keystream[24:], pt2)
print(pt1.decode())

#<!-- temporary password : My2uperPassphras3 -->
