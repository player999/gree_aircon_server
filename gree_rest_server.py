#!/usr/bin/python3.9
# Based on gree-remote repository on github

import sys
import json
import socket
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask
from flask import request as rqst
from requests.auth import HTTPDigestAuth
import flask_httpauth

global config

app = Flask(__name__)
app.config["SECRET_KEY"] = "Get#VcP25gPN"
digest_auth = flask_httpauth.HTTPDigestAuth()

GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"

@digest_auth.get_password
def get_password(username: str):
    if username == config["user"]:
        return config["pass"]
    else:
        return None

def send_data(ip, port, data):
    s = socket.socket(type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.sendto(data, (ip, port))
    return s.recv(1024)

def create_request(tcid, pack_encrypted, i=0):
    return '{"cid":"app","i":' + str(i) + ',"t":"pack","uid":0,"tcid":"' + tcid + '","pack":"' + pack_encrypted + '"}'

def add_pkcs7_padding(data):
    length = 16 - (len(data) % 16)
    padded = data + chr(length) * length
    return padded

def create_cipher(key):
    return Cipher(algorithms.AES(key.encode('utf-8')), modes.ECB(), backend=default_backend())

def decrypt(pack_encoded, key):
    decryptor = create_cipher(key).decryptor()
    pack_decoded = base64.b64decode(pack_encoded)
    pack_decrypted = decryptor.update(pack_decoded) + decryptor.finalize()
    pack_unpadded = pack_decrypted[0:pack_decrypted.rfind(b'}') + 1]
    return pack_unpadded.decode('utf-8')

def decrypt_generic(pack_encoded):
    return decrypt(pack_encoded, GENERIC_KEY)

def encrypt(pack, key):
    encryptor = create_cipher(key).encryptor()
    pack_padded = add_pkcs7_padding(pack)
    pack_encrypted = encryptor.update(bytes(pack_padded, encoding='utf-8')) + encryptor.finalize()
    pack_encoded = base64.b64encode(pack_encrypted)
    return pack_encoded.decode('utf-8')


def encrypt_generic(pack):
    return encrypt(pack, GENERIC_KEY)

def device_configuration(ip: str) -> dict:
    s = socket.socket(type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(b'{"t":"scan"}', (config["ip_broadcast"], 7000))
    device_config = None
    try:
        (data, address) = s.recvfrom(1024)
        if len(data) == 0:
            return device_config
        resp = json.loads(data[0:data.rfind(b"}") + 1])
        pack = json.loads(decrypt_generic(resp['pack']))
        device_config = {"cid": pack['cid']}
    except:
        pass
    pack = '{"mac":"%s","t":"bind","uid":0}' % device_config["cid"]
    pack_encrypted = encrypt_generic(pack)

    request = create_request(device_config['cid'], pack_encrypted, 1)
    result = send_data(ip, 7000, bytes(request, encoding='utf-8'))
    response = json.loads(result)
    if response["t"] == "pack":
        pack = response["pack"]
        pack_decrypted = decrypt_generic(pack)
        bind_resp = json.loads(pack_decrypted)
        if bind_resp["t"] == "bindok":
            key = bind_resp['key']
    device_config["key"] = key
    return device_config

def get_device_params(dev_config: dict) -> dict:
    pack = '{"cols":["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet",' \
    '"Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt"],"mac":"' + dev_config["cid"] + '","t":"status"}'
    pack_encrypted = encrypt(pack, dev_config["key"])
    request = '{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"%s","uid":0}' \
              % (pack_encrypted, dev_config["cid"])

    result = send_data(config["ip"], 7000, bytes(request, encoding='utf-8'))
    response = json.loads(result)

    params = {}
    if response["t"] == "pack":
        pack = response["pack"]
        pack_decrypted = decrypt(pack, dev_config["key"])
        pack_json = json.loads(pack_decrypted)
        for col, dat in zip(pack_json['cols'], pack_json['dat']):
            params[col] = dat
    return params

def set_device_params(dev_config: dict, params: dict):
    opts = list(params.keys())
    ps = list(map(lambda x: params[x], opts))
    pack = '{"opt":%s,"p":%s,"t":"cmd"}' % (json.dumps(opts), json.dumps(ps))
    pack_encrypted = encrypt(pack, dev_config["key"])

    request = '{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"%s","uid":0}' \
              % (pack_encrypted, dev_config["cid"])
    result = send_data(config["ip"], 7000, bytes(request, encoding='utf-8'))

    response = json.loads(result)
    if response["t"] == "pack":
        pack = response["pack"]
        pack_decrypted = decrypt(pack, dev_config["key"])
        pack_json = json.loads(pack_decrypted)
        if pack_json['r'] != 200:
            print('Failed to set parameter')

@app.route('/set_properties', methods=['POST'])
@digest_auth.login_required
def url_set_prop():
    dev_con = device_configuration(config["ip"])
    if rqst.method == 'POST':
        set_device_params(dev_con, rqst.json)
    return json.dumps("{}"), 200, {'Content-Type': 'application/json'}

@app.route('/get_properties')
@digest_auth.login_required
def url_get_props():
    dev_con = device_configuration(config["ip"])
    prms = get_device_params(dev_con)
    return json.dumps(prms), 200, {'Content-Type': 'application/json'}

if __name__ == "__main__":
    global config
    if len(sys.argv) == 2:
        config_file = sys.argv[1]
    else:
        config_file = "configuration.json"
    config = None
    with open(config_file, "r") as fconf:
        config = json.loads(fconf.read())
        app.config["SECRET_KEY"] = config["secret_key"]
    app.run(host="0.0.0.0", port=8050, debug=config["debug"])
    #devc = device_configuration(config["ip"])
    #dparams = get_device_params(devc)
    #set_device_params(devc, dparams)