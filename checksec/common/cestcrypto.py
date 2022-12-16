import base64

from tinyec import registry
from tinyec import ec
import secrets, hashlib
from Crypto.Cipher import AES

def generate_ECDH_key():
  curve = registry.get_curve('secp256r1') #AKA "P-256"
  privd = secrets.randbelow(curve.field.n)
  pub_key = privd * curve.g
  priv_point = ec.Point(curve, x=pub_key.x, y=pub_key.y)
  priv_keypair = ec.Keypair(curve, pub=priv_point, priv=privd)

  ecdh_priv = ec.ECDH(priv_keypair)

  jwk = {
  'x': base64.urlsafe_b64encode(pub_key.x.to_bytes(32, byteorder='big')).decode('ascii'), 
  'y': base64.urlsafe_b64encode(pub_key.y.to_bytes(32, byteorder='big')).decode('ascii'), 
  'd': base64.urlsafe_b64encode(privd.to_bytes(32, byteorder='big')).decode('ascii'),
  "ext": True,
  "key_ops": [
    "deriveKey",
    "deriveBits"
  ],
  'kty': 'EC', 
  'crv': 'P-256' 
  }

  return (jwk, ecdh_priv)
  
def to_pub(priv_key):
  pub_key = {
    "kty": "EC",
    "crv": "P-256",
    'x': priv_key["x"], 
    'y': priv_key["y"]
  }
  return pub_key


def ecc_point_to_256_bit_key(point):
    return point.x

def exchange(priv, pub):
  curve = registry.get_curve('secp256r1') #AKA "P-256"

  pubx = int.from_bytes(base64.urlsafe_b64decode(pub["x"]), byteorder="big")
  puby = int.from_bytes(base64.urlsafe_b64decode(pub["y"]), byteorder="big")
  pub_point = ec.Point(curve, x=pubx, y=puby)
  pub_keypair = ec.Keypair(curve, pub=pub_point)

  priv = keys['priv']
  privx = int.from_bytes(base64.urlsafe_b64decode(priv["x"]), byteorder="big")
  privy = int.from_bytes(base64.urlsafe_b64decode(priv["y"]), byteorder="big")
  privd = int.from_bytes(base64.urlsafe_b64decode(priv["d"]), byteorder="big")

  priv_point = ec.Point(curve, x=privx, y=privy)
  priv_keypair = ec.Keypair(curve, pub=priv_point, priv=privd)

  ecdh_priv = ec.ECDH(priv_keypair)
  secret = ecdh_priv.get_secret(pub_keypair)

  k = ecc_point_to_256_bit_key(secret)
  base64K = base64.urlsafe_b64encode(k.to_bytes(32, byteorder='big')).decode('ascii')

  sharedKey = {
    'key_ops': [ 'encrypt', 'decrypt' ],
    'ext': True,
    'kty': 'oct',
    'k':base64K,
    'alg': 'A256GCM',
  }

  return sharedKey

def decrypt(obj): 
  sharedKeyBase64 = obj['sharedKey']['k']
  ivBase64 = obj['iv'] + '=='
  msgStr = obj['chipher']

  sharedKey = base64.urlsafe_b64decode(sharedKeyBase64)
  iv = base64.urlsafe_b64decode(ivBase64)
  chipher_and_auth_tag = base64.urlsafe_b64decode(ivBase64)
  chipher = chipher_and_auth_tag[:-16]
  auth_tag = chipher_and_auth_tag[-16:]
  aes = AES.new(sharedKey, AES.MODE_GCM, nonce=iv)
  plaintext = aesCipher.decrypt_and_verify(chipher, auth_tag)
  return plaintext

def encrypt(obj):
  sharedKeyBase64 = obj['sharedKey']['k']
  msgStr = obj['message']

  sharedKey = base64.urlsafe_b64decode(sharedKeyBase64)

  aes = AES.new(sharedKey, AES.MODE_GCM)
  cipher_part, auth_tag = aes.encrypt_and_digest(msgStr.encode('ascii'))

  cipher = base64.urlsafe_b64encode(cipher_part + authTag).decode('ascii')
  iv = base64.urlsafe_b64encode(aes.nonce.to_bytes(32, byteorder='big')).decode('ascii')
  
  return {
   'cipher':cipher,
   'iv': iv
  }

def dohash(string):
  h = hashlib.sha256()
  h.update(string)
  return h.digest()

