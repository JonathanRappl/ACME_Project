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
    server_dict = client.get_server_dict()
    nice_printer(server_dict, "SERVER DICT")
    client.get_fresh_nonce()
    client.create_account()
    # -------------------------------------
# -----------------------------------------------

if __name__ == "__main__":
    main()
