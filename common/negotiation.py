# -*- coding: utf-8 -*-

import flask
from flask import request, jsonify
import random
import json
import sys
import os
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

        if self.arguments.negotiation:
            if os.path.isfile("negotiations.conf"):
                data = json.loads(open("negotiations.conf","r").read())
        return

    def start(self):
        self.GenerateProtocolConfigurations()
        log = logging.getLogger('werkzeug')
        log.disabled = True
        server.name = "Egress Assess - Negotiation Mode"
        server.run(host="0.0.0.0")

    def GenerateProtocolConfigurations(self):

        global data

        for proto in self.protocols:
            password = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(12)])
            # Configure each protocol values depending Protocols being tested
            if proto.protocol.lower() == "ftp":

                if data["ftp"]["password"] == "null":
                    data["ftp"]["password"] = password

                proto.username = data["ftp"]["username"]
                proto.password = data["ftp"]["password"]
                proto.port = int(data["ftp"]["port"])
                data["ftp"]["enabled"] = "True"

            elif proto.protocol.lower() == "smb":

                if data["smb"]["password"] == "null" and data["smb"]["username"] == "null":
                    print("here")
                    data["smb"]["username"] = "null"
                    data["smb"]["password"] = "null"

                elif data["smb"]["password"] == "null" and data["smb"]["username"] != "null":
                    data["smb"]["password"] = password

                if data["smb"]["smb2"] == "True":
                    proto.smb2support = True

                proto.username = data["smb"]["username"]
                proto.password = data["smb"]["password"]
                proto.port = int(data["smb"]["port"])
                data["smb"]["enabled"] = "True"

            elif proto.protocol.lower() == "sftp":
                if data["sftp"]["password"] == "null":
                    data["sftp"]["password"] = password
                proto.username = data["sftp"]["username"]
                proto.password = data["sftp"]["password"]
                proto.port = int(data["sftp"]["port"])
                data["sftp"]["enabled"] = "True"

            elif proto.protocol.lower() == "http":
                proto.port = int(data["http"]["port"])
                data["http"]["enabled"] = "True"

            elif proto.protocol.lower() == "https":
                proto.port = int(data["https"]["port"])
                data["https"]["enabled"] = "True"

            elif proto.protocol.lower() == "icmp":
                data["icmp"]["enabled"] = "True"

            elif proto.protocol.lower() == "dns":
                data["dns"]["enabled"] = "True"
                data["dns_resolved"]["enabled"] = "True"

            elif proto.protocol.lower() == "smtp":
                proto.port = int(data["smtp"]["port"])
                data["smtp"]["enabled"] = "True"

        return

    def RetrieveServerProtocols(self):
        return

    @server.route('/get-negotiations', methods=['GET'])
    def ServeProtocolInformation():
        print("[+] Retrieving Negotiations from client: %s" %request.remote_addr)
        return jsonify(data)

    '''
    @server.route("/negotiation-enabled", methods=["GET"])
    def IsEnabled():
        return jsonify(True)
    '''

    @server.route('/send-status', methods=["GET"])
    def CheckInOutput():

        if request.args.get("protocol") and request.args.get("started"):
            print("[+] %s Server Has Been Started" %request.args.get("protocol").upper())

        if request.args.get("error"):
            print("(!) Issues Start %s Server...skipping" %request.args.get("protocol").upper())

        if request.args.get("stop"):
            print("[+] %s Server is Stopping" %request.args.get("protocol").upper())

        if request.args.get("complete") and request.args.get("protocol"):
            print("[+] %s Data Finshed Sending From Client: %s" %(request.args.get("protocol").upper(),request.remote_addr))

        if request.args.get("protocol") and request.args.get("send"):
            print("[+] Client %s attempting to send %s data" %(request.remote_addr,request.args.get("protocol").upper()))

        return jsonify({200:"Success"})
