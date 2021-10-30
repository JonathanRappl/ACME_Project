# --------------------IMPORTS--------------------
import argparse
import requests
import acme_client
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
    parser.add_argument('--revoke', required=False)
    return vars(parser.parse_args())
# -----------------------------------------------

# -----------------NICE PRINTER------------------
def nice_printer(stuff : object, head : str):
    width = 150
    buff = (width-len(head))//2
    print(buff*"-", head, (width-len(head)-buff)*"-")
    print(stuff)
    print((2+width)*"-")
# -----------------------------------------------

# ---------------------MAIN----------------------
def main():
    arguments = argument_parser()
    nice_printer(arguments, "ARGUMENTS")

    # ---------------CLIENT----------------
    client = acme_client.ACME_Client(arguments['dir'])
    client.get_server_dict()
    # -------------------------------------
    client.get_fresh_nonce()
    # -------------------------------------
    client.create_account()
    # -------------------------------------
    client.request_certificate(arguments['domain'])
    # -------------------------------------
    client.fetch_challenges()
    # -------------------------------------
    client.resolve_challenges(arguments['challenge'])

# -----------------------------------------------

if __name__ == "__main__":
    main()
