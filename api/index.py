from flask import Flask, send_file

from cybershield_server import HTML_FILE


app = Flask(__name__)


@app.get("/")
@app.get("/scam-checker.html")
def index():
    return send_file(HTML_FILE, mimetype="text/html", etag=False)
