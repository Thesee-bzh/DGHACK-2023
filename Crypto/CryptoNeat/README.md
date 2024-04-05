# Crypto / CryptoNeat

## Challenge
Une information tres secrète est dissimulée dans cette page web.

Saurez-vous la trouver ?

## Inputs
- website at http://cryptoneat2.chall.malicecyber.com/

## Solution
Heading to this website, we see a simple page entitled 'very protected page', asking for a password. No links, nothing else.

This interesting part is in the javascript: [script.js](./script.js)

We have an `encrypt` function that uses the `CryptoJS` library and implements AES encryption in `CTR mode` with `PKCS7` padding:

```javascript
// Encrypt text with password
function encrypt(msg, password) {
  key = derivePassword(password);
  var encrypted = CryptoJS.AES.encrypt(msg, key, {
    iv: iv,
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CTR,
  });
  return iv.toString() + encrypted.toString();
}
exports.encrypt = encrypt;
```

The cipher key is derived using function `derivePassword`:
```javascript
// Derive password
function derivePassword(password) {
  var key = CryptoJS.PBKDF2(password, "", {
    keySize: 128 / 32,
    iterations: 1000
  });
  return key;
}
exports.derivePassword = derivePassword;
```

The `decrypt` function is also available to us, but that is not too relevant.

We also have `two encrypted messages` (encrypted and base64-encoded), let's call them `C1` and `C2`.

The assumption here is that the same key has been used to encrypt both messages, which may completely break the security in `AES CTR mode`, since we have:
```
C1 = P1 ^ F(key)
C2 = P2 ^ F(key)
```

With `P1` and `P2` the corresponding plaintext messages for `C1` and `C2` and `^` the XOR operator.

From this, we can deduce:
```
C1 ^ C2 = P1 ^ P2
```

So by XORing `C1` and `C2`, we effectively get `P1 ^ P2`. Which means that, if by any chance, we get the plaintext of one of them, say `P2`, then we can retrieve `P1` !

And guess what, we also have a plaintext in the javascript, which is fair to assume to be `P2`:
```javascript
exports.cryptoThanks = "Build with love, kitties and flowers";
```

`So in case the key was indeed reused, then we can retrieve P1`.

Let's implement it in python.

First we need to carefully pad the given plaintext `P2`, since encryption uses `PKCS7 padding`. `PKCS7 padding` is easy: the padding value is equal to the total number of padding bytes that are added. `AES CTR mode` always uses a block size of 16 bytes and `P2 = "Build with love, kitties and flowers"` length is 36, so we need to add `12 padding bytes` (36 + 12 = 48 = 0 mod 16). So the padding value is 12=0x0c:

```python
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
print(pt2)
```

```console
$ python3 sol.py
b'Build with love, kitties and flowers\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
```

Then we grab the two encrypted messages, xor them together, and finally xor the result with the known plaintext:
```python
# encrypted
b64_msg1 = '34aff6de8f8c01b25c56c52261e49cbddQsBGjy+uKhZ7z3+zPhswKWQHMYJpz7wffAe4Es/bwrJmMo99K\
v7XJ8P63TbN/8X'
msg1 = b64decode(b64_msg1)

b64_msg2 = '34aff6de8f8c01b25c56c52261e49cbdC19FW3jqqqxd6G/z0fcpnOSIBsUSvD+jZ7E9/VkscwDMrdk9i9\
efIvJw1Fj6Fs0R'
msg2 = b64decode(b64_msg2)

# Extract Keystream
keystream = xor(msg1[:len(msg2)], msg2)

# Decode msg1
pt1 = xor(keystream[24:], pt2)
print(pt1.decode())
```

That way, we recover a password to access the website:
```console
$ python3 sol.py
<!-- temporary password : My2uperPassphras3 -->

```

Logging in on the website, we get the flag.

## Python code
Complete solution in [sol.py](./sol.py)

## Flag
> DGHACK{w3ak_pa22word2_ar3n-t_n3at}
