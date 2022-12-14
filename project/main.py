# --------------------IMPORTS--------------------
import argparse
import time
import requests
import acme_client
import dns_server
import subprocess

from dnslib.server import DNSServer
# -----------------------------------------------

# --------------------PARSER---------------------
def argument_parser():
    """
    Returns a dictionary of the arguments with their corresponding value.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('challenge', choices=["dns01", "http01"])
    parser.add_argument('--dir', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--domain', required=True, action='append')
    parser.add_argument('--revoke', required=False, action='store_true')
    parser.add_argument('--local', required=False, action='store_true')
    return parser.parse_args()
# -----------------------------------------------

# -----------------NICE PRINTER------------------
def nice_printer(stuff : object, head : str):
    width = 150
    buff = (width-len(head))//2
    print(buff*"-", head, (width-len(head)-buff)*"-")
    print(stuff)
    print((2+width)*"-")

def nice_announcement_printer(head : str):
    width = 150
    margin = 0
    buff = (width-len(head))//2
    print((buff-margin)*"-", head, (width-len(head)-buff-margin)*"-")
# -----------------------------------------------

# ---------------------MAIN----------------------
def main():
    arguments_no_vars = argument_parser()
    arguments = vars(arguments_no_vars)
    nice_printer(arguments, "ARGUMENTS")

    # -------------DNS SERVER--------------
    dns, resolver = dns_server.create_dns_server(arguments['record'])
    dns.start_thread()
    nice_announcement_printer("DNS SERVER UP AND RUNNING")
    # -------------------------------------

    # -------------HTTP SERVER-------------
    if arguments['challenge'] == 'http01':
        http = subprocess.Popen(['python3', 'http_server.py', arguments['record']])
        nice_announcement_printer("HTTP CHALLENGE SERVER UP AND RUNNING")
    # -------------------------------------

    # ---------------CLIENT----------------
    client = acme_client.ACME_Client(arguments['dir'], resolver)
    nice_printer(client.get_server_dict(), "SERVER DICT")
    # -------------------------------------
    client.get_fresh_nonce()
    if not arguments['local']:
        time.sleep(5) # -------------------
    client.create_account()
    if not arguments['local']:
        time.sleep(5) # -------------------
    client.request_certificate(arguments['domain'])
    if not arguments['local']:
        time.sleep(5) # -------------------
    client.fetch_challenges()
    if not arguments['local']:
        time.sleep(5) # -------------------
    client.resolve_challenges(arguments['challenge'], arguments['record'])
    # -------------------------------------
    client.finalize_order()
    if not arguments['local']:
        time.sleep(5) # -------------------
    certificate = client.get_certificate()
    open('certs', 'w').write(certificate)

    # ---------------REVOKE----------------
    if arguments['revoke']:
        client.revoke_cert()
    # -------------------------------------

    # -------------HTTPS SERVER------------
    https = subprocess.Popen(['python3', 'https_server.py', arguments['record']])
    # -------------------------------------
    
    # --------------SHUTDOWN---------------
    shutdown = subprocess.Popen(['python3', 'http_shutdown.py', arguments['record']])
    shutdown.wait()
    # -------------------------------------

    # -----------HTTP SERVER KILL----------
    https.kill()
    if arguments['challenge'] == 'http01':
        http.kill()
    # -------------------------------------

# -----------------------------------------------

if __name__ == "__main__":
    main()
