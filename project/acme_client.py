# --------------------IMPORTS--------------------
from typing import List
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
class Challenge:
    def __init__(self, identifier_value : str, fetched_challenge : dict) -> None:
        self.identifier_value = identifier_value
        self.type = fetched_challenge['type']
        self.url = fetched_challenge['url']
        self.token = fetched_challenge['token']
        self.status = fetched_challenge['status']
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
    
    def create_account(self) -> None:
        jwk = self.jws.create_jwk(self.jws.public_key)
        header = self.jws.create_jws_header(jwk, None, self.replay_nonce, self.server_dict['newAccount'])
        body = TOS_BODY
        jws = self.jws.create_jws(header, body)
        response = requests.post(self.server_dict['newAccount'], data=json.dumps(jws), headers=CT_HEADER, verify='pebble.minica.pem')
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
    
    def request_certificate(self, domains : list) -> None:
        identifiers = []
        for domain in domains:
            identifiers.append({"type": "dns", "value": domain})
        header = self.jws.create_jws_header(None, self.kid, self.replay_nonce, self.server_dict['newOrder'])
        body = {"identifiers": identifiers}
        jws = self.jws.create_jws(header, body)
        response = requests.post(self.server_dict['newOrder'], data=json.dumps(jws), headers=CT_HEADER, verify='pebble.minica.pem')
        if response.status_code == 201:
            client_nice_announcement_printer("CERTIFICATE ORDER SUCCESSFULL")
            self.domains = domains
            self.authorizations = response.json()['authorizations']
            self.finalize = response.json()['finalize']
            self.location = response.headers['Location']
            self.replay_nonce = response.headers['Replay-Nonce']
        else:
            client_nice_announcement_printer("CERTIFICATE ORDER UNSUCCESSFULL")
        # client_nice_printer(response.status_code, "REQUEST CERTIFICATE STATUS CODE")
        # client_nice_printer(response.json(), "REQUEST CERTIFICATE JSON")
        # client_nice_printer(json.dumps(dict(response.headers)), "REQUEST CERTIFICATE RESPONSE HEADERS")
    
    def fetch_challenges(self) -> None:
        self.challenges = []
        for authorization in self.authorizations:
            header = self.jws.create_jws_header(None, self.kid, self.replay_nonce, authorization)
            jws = self.jws.create_jws(header, None)
            response = requests.post(authorization, data=json.dumps(jws), headers=CT_HEADER, verify='pebble.minica.pem')
            self.replay_nonce = response.headers['Replay-Nonce']
            for fetched_challenge in response.json()['challenges']:
                self.challenges.append(Challenge(response.json()['identifier']['value'], fetched_challenge))
        client_nice_announcement_printer("CHALLENGES FETCHED")
    
    def resolve_challenges(self, challenge_type : str) -> None:
        if challenge_type == 'dns01':
            for challenge in self.challenges:
                if challenge.type == 'dns-01':
                    pass



    
        
if __name__ == "__main__":
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    open("private_key.pem", "w").write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode('utf-8'))

    
# -----------------------------------------------