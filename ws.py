from flask import Flask, Blueprint, request
from flask_sock import Sock, Server, ConnectionClosed
from utils import *
import models
import os

WS_PING_INTERVAL = int(os.environ['WS_PING_INTERVAL'])
WS_MAX_MSG_SIZE = parse_int(os.environ['WS_MAX_MSG_SIZE'])

__version__ = '0.1'

app = Blueprint('ws', __name__)
sock = Sock()

streams = []
ws_stream = []

@sock.route("/editor/<token>", app)
def editor(ws: Server, token: str):
    stream: models.Stream = models.Stream.query.filter(models.Stream.token==token).first()

    if (not stream) or (stream in streams):
        ws.close(1000, "Stream not found")
        return
    
    streams.append(stream)
    ws_stream.append(ws)

    stream_ind = len(streams) - 1
    
    # echo route for test
    while True:
        try:
            data = ws.receive()
            ws.send(data)
        except ConnectionClosed:
            break
    
    try:
        streams.pop(stream_ind)
        ws_stream.pop(stream_ind)
    except:
        pass

    models.remove(stream)
    models.save()

    print(f"close code: {ws.close_reason}, msg: {ws.close_message}")


def __init__(flask_app: Flask):
    flask_app.config['SOCK_SERVER_OPTIONS'] = {'ping_interval': WS_PING_INTERVAL, 'max_message_size': WS_MAX_MSG_SIZE}
    sock.init_app(flask_app)
