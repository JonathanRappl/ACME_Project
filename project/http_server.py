from flask import Flask, send_from_directory
import argparse

app = Flask(__name__)

@app.route("/")
def index():
    return open("certs", "r").read()
@app.route("/.well-known/acme-challenge/<path:token>")
def get_token(token):
    return send_from_directory('acme-challenge', token)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('record')
    arguments = vars(parser.parse_args())
    app.run(arguments['record'], 5002)

if __name__ == "__main__":
    main()