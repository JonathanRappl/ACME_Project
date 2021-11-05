# --------------------IMPORTS--------------------
import base64
import json
from typing import List
from collections import OrderedDict

import acme_constants

from math import ceil, log2
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.base import CertificateSigningRequest
from cryptography.hazmat import backends
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
# -----------------------------------------------

def bytes_from_int(value : int) -> bytes:
    """
    Takes a value of type integer and returns the corresponding unsigned bytes
    """
    return int.to_bytes(value, ceil(log2(value)/8), 'big', signed=False)

def int_to_base64(value : int) -> bytes:
    return base64.urlsafe_b64encode(bytes_from_int(value)).rstrip(b'=')

def encode(dictionary : dict) -> bytes:
    """
    Encodes a dictionary in base64 representation
    """
    return base64.urlsafe_b64encode(json.dumps(dictionary, separators=(",", ":")).encode('utf-8')).rstrip(b'=')

def decode(data : bytes) -> dict:
    """
    Decodes the given data to a dictionary
    """
    return json.loads(base64.urlsafe_b64decode(data).decode('utf-8'))

class JWS:
    def __init__(self, private_key : RSAPrivateKey) -> None:
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    def create_jws (self, header : dict, payload : dict) -> dict:
        # print("Header:", header)
        header = encode(header)
        if payload != None:
            payload = encode(payload)
        else:
            payload = b''

        signature_data = header + b'.' + payload
        signature = base64.urlsafe_b64encode(self.private_key.sign(signature_data, PKCS1v15(), SHA256())).rstrip(b'=')
        
        return {"protected": header.decode('utf-8'), "payload": payload.decode('utf-8'), "signature": signature.decode('utf-8')}#header + b'.' + payload + b'.' + signature# 

    def create_jwk(self, public_key : RSAPublicKey) -> dict:
        return {
            "alg": "RS256",
            "kty": "RSA",
            "n" : int_to_base64(public_key.public_numbers().n).decode('utf-8'),
            "e" : int_to_base64(public_key.public_numbers().e).decode('utf-8')
        }

    def create_jws_header(self, jwk : dict, kid : str, nonce : str, url : str) -> dict:
        header = {
            "alg": "RS256",
            "nonce": nonce,
            "url": url,
        }
        if kid == None:
            # We wanna make a new account
            header["jwk"] = jwk
        else: 
            header["kid"] = kid
        # print("Header2:", header)
        return header
    
    def create_jwk_thumbprint(self) -> bytes:
        jwk_no_order = self.create_jwk(self.public_key)
        jwk = OrderedDict()
        jwk['e'] = jwk_no_order['e']
        jwk['kty'] = jwk_no_order['kty']
        jwk['n'] = jwk_no_order['n']
        hasher = Hash(SHA256(), default_backend())
        hasher.update(json.dumps(jwk, separators=(",", ":")).encode('utf-8'))
        digest = hasher.finalize()
        self.jwk_thumbprint = base64.urlsafe_b64encode(digest).rstrip(b'=')
        return self.jwk_thumbprint

    def create_key_authorization_hash(self, token : str) -> bytes:
        jwk_thumbprint = self.create_jwk_thumbprint()
        key_authorization = token.encode('utf-8') + b'.' + jwk_thumbprint
        hasher = Hash(SHA256(), default_backend())
        hasher.update(key_authorization)
        digest = hasher.finalize()
        key_authorization_bytes = base64.urlsafe_b64encode(digest).rstrip(b'=')
        return key_authorization_bytes

    def create_csr(self, domains : List[str]) -> str:
        self.csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        csr_private_bytes = self.csr_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        open('csr_key', 'w').write(csr_private_bytes.decode())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain) for domain in domains
            ]),
            critical=False,
        ).sign(self.csr_key, SHA256())
        return base64.urlsafe_b64encode(csr.public_bytes(Encoding.DER)).rstrip(b'=').decode('utf-8')
        

if __name__ == "__main__":
    #header = {"typ": "JWT", "alg": "HS256"}
    #payload = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True} #1835101537
    #print(encode(header))
    #print(encode(payload))
    #print(jws.create_jws(header, payload))
    #print(int_to_base64(public_key.public_numbers().x).decode('utf-8'))
    key = load_pem_private_key(open("./private_key.pem").read().encode('utf-8'), password=None)
    print(key)
    jws = JWS(key)
    jws.create_key_authorization()
    # print(key.public_key().curve)
    # public_key = jws.private_key.public_key()
    # key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    # print(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode('utf-8'))