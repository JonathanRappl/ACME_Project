# --------------------IMPORTS--------------------
import time
from typing import List
import requests
import json

from requests.api import head
from requests.models import Response

from acme_constants import *
from jws import JWS
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key

from dns_server import CustomResolver
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

# ------------------CHALLENGE-------------------
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
    def __init__(self, dir : str, resolver : CustomResolver) -> None:
        self.dir = dir
        self.jws = self.initialize_jws()
        self.resolver = resolver
        
    
    def initialize_jws(self) -> JWS:
        # ---------- GENERATE A NEW KEY AND SAVE IT ----------
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        open("private_key.pem", "w").write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode('utf-8'))
        # ----------------------------------------------------
        key = load_pem_private_key(open("./private_key.pem").read().encode('utf-8'), password=None)
        return JWS(key)

    def get_server_dict(self) -> dict:
        """
        Returns the dict of the pebble server and sets self.server_dict to that value
        """
        response = requests.get(self.dir, verify='pebble.minica.pem')
        if response.status_code == 200:
            self.server_dict = response.json()
            client_nice_announcement_printer("SERVER DICT FETCHED")
            return self.server_dict
        else:
            client_nice_announcement_printer("SERVER DICT COULD NOT BE FETCHED")


    def get_fresh_nonce(self) -> str:
        """
        Returns a fresh nonce requested from the server and sets self.replay_nonce to that value
        """
        response = requests.head(self.server_dict['newNonce'], verify='pebble.minica.pem')
        if response.status_code == 200:
            self.replay_nonce = response.headers['Replay-Nonce']
            client_nice_announcement_printer("FRESH NONCE FETCHED")
            return self.replay_nonce
        else:
            client_nice_announcement_printer("FRESH NONCE COULD NOT BE FETCHED")
        
    def retry_bad_nonce(self, url : str, data : dict, headers : dict) -> Response:
        """
        We call this if we get a bad nonce error code
        """
        # CURRENTLY WE ARE NOT USING THIS FUNCTION
        response_valid = False
        while not response_valid:
            response = requests.post(url, data=data, headers=headers, verify='pebble.minica.pem')
            if response.status_code == 400 and response.json()["type"] == 'urn:ietf:params:acme:error:badNonce':
                client_nice_announcement_printer("NONCE REJECTED, RETRYING...")
            else:
                response_valid = True
                # self.replay_nonce = response.headers['Replay-Nonce']
                client_nice_announcement_printer("GOTTEN VALID RESPONSE")
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
    
    def resolve_challenges(self, challenge_type : str, record : str) -> None:
        client_nice_announcement_printer("RESOLVING CHALLENGES...")
        for challenge in self.challenges:
            if challenge_type == 'dns01' and challenge.type == 'dns-01':
                client_nice_printer(challenge.__dict__, "RESOLVING DNS CHALLENGE")
                self.resolve_dns_challenge(challenge, record)
            elif challenge_type == 'http01' and challenge.type == 'http-01':
                client_nice_printer(challenge.__dict__, "RESOLVING HTTP CHALLENGE")
                self.resolve_http_challenge(challenge)
    
    def resolve_dns_challenge(self, challenge : Challenge, record : str) -> None:
        key_authorization_hash = self.jws.create_key_authorization_hash(challenge.token)
        client_nice_printer(challenge.identifier_value, "CHALLENGE IDENTIFIER VALUE")
        self.resolver.zones_dict[challenge.identifier_value] = ["_acme-challenge.{}. 300 IN TXT {}".format(challenge.identifier_value, key_authorization_hash.decode('utf-8')), "_acme-challenge.{}. 300 IN A {}".format(challenge.identifier_value, record)]
        header = self.jws.create_jws_header(None, self.kid, self.replay_nonce, challenge.url)
        jws = self.jws.create_jws(header, {})
        response = requests.post(challenge.url, data=json.dumps(jws, separators=(",", ":")), headers=CT_HEADER, verify='pebble.minica.pem')
        self.replay_nonce = response.headers['Replay-Nonce']
        client_nice_printer(response.status_code, "DNS RESPONSE STATUS CODE")
        client_nice_printer(response.json(), "DNS RESPONSE JSON")
        client_nice_printer(json.dumps(dict(response.headers)), "DNS RESPONSE RESPONSE HEADERS")

    def resolve_http_challenge(self, challenge : Challenge) -> None:
        pass
    
    def finalize_order(self) -> None:
        csr = self.jws.create_csr(self.domains)
        header = self.jws.create_jws_header(None, self.kid, self.replay_nonce, self.finalize)
        jws = self.jws.create_jws(header, {"csr": csr})
        response = requests.post(self.finalize, data=json.dumps(jws), headers=CT_HEADER, verify='pebble.minica.pem')
        self.replay_nonce = response.headers['Replay-Nonce']
        client_nice_printer(response.status_code, "FINALIZE STATUS CODE")
        client_nice_printer(response.json(), "FINALIZE JSON")
        client_nice_printer(json.dumps(dict(response.headers)), "FINALIZE RESPONSE HEADERS")
        if response.status_code == 403: 
            if response.json()['type'] == 'urn:ietf:params:acme:error:orderNotReady':
                header = self.jws.create_jws_header(None, self.kid, self.replay_nonce, self.location)
                jws = self.jws.create_jws(header, None)
                response = requests.post(self.location, data=json.dumps(jws), headers=CT_HEADER, verify='pebble.minica.pem')
                self.replay_nonce = response.headers['Replay-Nonce']
                client_nice_printer(response.status_code, "PAG STATUS CODE")
                client_nice_printer(response.json(), "PAG JSON")
                client_nice_printer(json.dumps(dict(response.headers)), "PAG RESPONSE HEADERS")
        if response.json()['status'] == 'processing':
            client_nice_announcement_printer("ORDER STILL PROCESSING, SENDING PAG")
            time.sleep(5)
            header = self.jws.create_jws_header(None, self.kid, self.replay_nonce, self.location)
            jws = self.jws.create_jws(header, None)
            response = requests.post(self.location, data=json.dumps(jws), headers=CT_HEADER, verify='pebble.minica.pem')
            self.replay_nonce = response.headers['Replay-Nonce']
            client_nice_printer(response.status_code, "PAG STATUS CODE")
            client_nice_printer(response.json(), "PAG JSON")
            client_nice_printer(json.dumps(dict(response.headers)), "PAG RESPONSE HEADERS")



    
        
if __name__ == "__main__":
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    open("private_key.pem", "w").write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode('utf-8'))

    
# -----------------------------------------------