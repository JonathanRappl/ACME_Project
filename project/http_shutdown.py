from flask import Flask
import os
import signal
import argparse
from acme_client import client_nice_announcement_printer

app = Flask(__name__)

@app.route("/shutdown")
def shutdown():
    client_nice_announcement_printer("BYE BYE")
    os.kill(os.getpid(), signal.SIGTERM)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('record')
    arguments = vars(parser.parse_args())
    app.run(arguments['record'], 5003)

if __name__ == "__main__":
    main()