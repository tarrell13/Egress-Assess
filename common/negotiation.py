# -*- coding: utf-8 -*-

import flask
from flask import request, jsonify
import random
import logging
import string

server = flask.Flask(__name__)
data = {}

class Negotiation(object):

    def __init__(self,arguments,protocols=None):

        global data

        self.arguments = arguments
        self.protocols = protocols
        self.server = None

        data = {
            "https": None,
            "http": None,
            "smtp": None,
            "icmp": False,
            "dns": False,
            "ftp": {
                "port": None,
                "username": "ftp_user",
                "password": None
            },
            "smb": {
                "port": None,
                "username": "smb_user",
                "password": None
            },
            "sftp": {
                "port": None,
                "username": "sftp_user",
                "password": None
            }
        }


        return

    def start(self):
        self.GenerateServerProtocolInformation()
        log = logging.getLogger('werkzeug')
        log.disabled = True
        server.name = "Egress Assess - Negotiation Mode"
        server.run(host="0.0.0.0")

    def GenerateServerProtocolInformation(self):
        global data

        for proto in self.protocols:

            password = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(12)])

            # Configure each protocol values depending Protocols being tested
            if proto.protocol.lower() == "https":
                data["https"] = proto.port
            elif proto.protocol.lower() == "http":
                data["http"] = proto.port
            elif proto.protocol.lower() == "smtp":
                data["smtp"] = proto.port
            elif proto.protocol.lower() == "icmp":
                data["icmp"] = True
            elif proto.protocol.lower() == "dns":
                data["dns"] = True
            elif proto.protocol.lower() == "ftp":
                data["ftp"]["port"] = proto.port
                data["ftp"]["password"] = password
            elif proto.protocol.lower() == "smb":
                data["smb"]["port"] = proto.port
                data["smb"]["password"] = password
            elif proto.protocol.lower() == "sftp":
                data["sftp"]["port"] = proto.port
                data["sftp"]["password"] = password

        return

    def RetrieveServerProtocols(self):
        return

    @server.route('/get-negotiations', methods=['GET'])
    def ServeProtocolInformation():
        client_address = request.args.get("address")
        print("[+] Retrieving Negotiations from client: %s" %client_address)
        return jsonify(data)

    @server.route('/checkin-status', methods=["GET"])
    def CheckInOutput():
        if request.args.get("protocol"):
            print("[+] %s Server Has Been Started" %request.args.get("protocol").upper())

        return jsonify({200:"Success"})
