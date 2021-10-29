# --------------------IMPORTS--------------------
import requests
import json

from acme_constants import *
from jws import JWS
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
# -----------------------------------------------

# -------------CLIENT NICE PRINTERS--------------
def client_nice_printer(stuff : object, head : str):
    width = 150
    margin = 25
    buff = (width-len(head))//2
    print((buff-25)*"-", head, (width-len(head)-buff-margin)*"-")
    print(stuff)
    print((2+width-2*margin)*"-")

def client_nice_announcement_printer(head : str):
    width = 150
    margin = 25
    buff = (width-len(head))//2
    print((buff-25)*"-", head, (width-len(head)-buff-margin)*"-")
# -----------------------------------------------

# ------------------ACME CLIENT------------------
class ACME_Client:
    def __init__(self, dir : str) -> None:
        self.dir = dir
        self.initialize_jws()
        
    
    def initialize_jws(self) -> JWS:
        # ---------- GENERATE A NEW KEY AND SAVE IT ----------
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        open("private_key.pem", "w").write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode('utf-8'))
        # ----------------------------------------------------
        key = load_pem_private_key(open("./private_key.pem").read().encode('utf-8'), password=None)
        self.jws = JWS(key)
    
    def create_account(self) -> None:
        jwk = self.jws.create_jwk(self.jws.public_key)
        header = self.jws.create_jws_header(jwk, None, self.replay_nonce, self.server_dict['newAccount'])
        body = TOS_BODY
        jws = self.jws.create_jws(header, body)
        response = requests.post(self.server_dict['newAccount'], data=json.dumps(jws), headers={"Content-Type": "application/jose+json"}, verify='pebble.minica.pem')
        if response.status_code == 201:
            client_nice_announcement_printer("NEW ACCOUNT CREATED")
            self.kid = response.headers['Location']
            self.replay_nonce = response.headers['Replay-Nonce']
        else:
            client_nice_announcement_printer("SERVER COULDN'T CREATE A NEW ACCOUNT")
        # client_nice_printer(response.status_code, "RESPONSE CODE")
        # client_nice_printer(response.json(), "RESPONSE JSON")
        # client_nice_printer(json.dumps(dict(response.headers)), "RESPONSE HEADERS")
        # client_nice_printer(response.headers['Location'], "KID")
        # client_nice_printer(response.headers['Replay-Nonce'], "NEW REPLAY NONCE")

    
    def get_server_dict(self) -> dict:
        """
        Returns the dict of the pebble server and sets self.server_dict to that value
        """
        response = requests.get(self.dir, verify='pebble.minica.pem').json()
        self.server_dict = response
        return response

    def get_fresh_nonce(self) -> str:
        """
        Returns a fresh nonce requested from the server and sets self.replay_nonce to that value
        """
        response = requests.head(self.server_dict['newNonce'], verify='pebble.minica.pem').headers['Replay-Nonce']
        self.replay_nonce = response
        return response
        
if __name__ == "__main__":
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    open("private_key.pem", "w").write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode('utf-8'))
    
# -----------------------------------------------