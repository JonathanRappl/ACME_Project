# --------------------IMPORTS--------------------
import time
from typing import Tuple
import acme_client

from dnslib.dns import RR, DNSQuestion, DNSRecord
from dnslib.server import DNSServer

from main import nice_printer, nice_announcement_printer
# -----------------------------------------------

# -------------------RESOLVER--------------------
class CustomResolver:
    """
        This class is based on the FixedResolver, but we have to make some changes
        because we cannot directly derive the self.rrs
    """
    def __init__(self,zone,record):
        self.zones_dict = {
            "challenge_id_vals" : []
        }
        self.record = record

    def resolve(self,request : DNSRecord, handler):
        self.zones_dict["challenge_id_vals"].sort(key = len)
        self.zones_dict["challenge_id_vals"].reverse()
        reply = request.reply()
        qname_str = str(request.q.qname)
        # nice_printer(qname_str, "QNAME STR")
        for challenge_id_val in self.zones_dict['challenge_id_vals']:
            if challenge_id_val in qname_str:
                reply.add_answer(*RR.fromZone(str(request.q.qname) + " 300 IN TXT " + self.zones_dict[challenge_id_val]['key_authorization_hash']))
                reply.add_answer(*RR.fromZone(str(request.q.qname) + " 300 IN A " + self.record))
                return reply
        # ELSE
        reply.add_answer(*RR.fromZone(str(request.q.qname) + " 300 IN A " + self.record))
        return reply
# -----------------------------------------------

# ------------------DNS SERVER-------------------
def create_dns_server(record : str) -> Tuple[DNSServer, CustomResolver]:
    resolver = CustomResolver({}, record)
    dns_server = DNSServer(resolver, port=10053, address=record)
    return dns_server, resolver
# -----------------------------------------------

if __name__ == "__main__":
    resolver = CustomResolver(["*. 60 A {}".format('1.2.3.4')])
    dns_server = DNSServer(resolver, port=10053, address="127.0.0.1")
    dns_server.start()
    
    #dns_server.stop()