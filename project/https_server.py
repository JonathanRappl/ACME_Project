from flask import Flask
import argparse

app = Flask(__name__)

@app.route("/")
def index():
    return open("certs", "r").read()
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('record')
    arguments = vars(parser.parse_args())
    app.run(arguments['record'], 5001, ssl_context = ('certs', 'csr_key'))

if __name__ == "__main__":
    main()
