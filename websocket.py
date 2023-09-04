from flask import Flask, Blueprint, request
from flask_sock import Sock, Server
from utils import *
import os

WS_PING_INTERVAL = int(os.environ['WS_PING_INTERVAL'])
WS_MAX_MSG_SIZE = parse_int(os.environ['WS_MAX_MSG_SIZE'])

__version__ = '0.1'

app = Blueprint('websocket', __name__)
sock = Sock()

@sock.route("/editor", app)
def editor(ws: Server):
    # echo route for test
    while True:
        data = ws.receive()
        ws.send(data)

def __init__(flask_app: Flask):
    flask_app.config['SOCK_SERVER_OPTIONS'] = {'ping_interval': WS_PING_INTERVAL, 'max_message_size': WS_MAX_MSG_SIZE}
    sock.init_app(flask_app)
