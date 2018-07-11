#!/usr/bin/env python
from flask_api import FlaskAPI, status
from flask import jsonify, g, request
from flask_cors import CORS
from flask_httpauth import HTTPTokenAuth
from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode
import json

import os

import ts3

app = FlaskAPI(__name__)
CORS(app)
auth = HTTPTokenAuth('Bearer')

# Config
app.config['JWT_SECRET'] = 'a long secret to verify jwt tokens' # Secret used for generation of auth token PLEASE CHANGE
#app.config['CRYPT_KEY'] = u'supersecretkeyv2'

if os.environ.get('TS_CRYPT_KEY'):
    app.config['CRYPT_KEY'] = json.loads(os.environ.get('TS_CRYPT_KEY'))
else:
    app.config['CRYPT_KEY'] = "CHANGEME" # Generate a key using keygen.py and paste it here

key = jwk.JWK(**app.config['CRYPT_KEY'])

class User():
    # ...

    def generate_auth_token(username, password, ip):
        payload = json_encode({ 'username': username, 'password': password, 'ip': ip })
        jwetoken = jwe.JWE(payload.encode('utf-8'), json_encode({"alg": "A256KW", "enc": "A256CBC-HS512"})) # creates token
        jwetoken.add_recipient(key)
        return jwetoken.serialize()

    @staticmethod
    def verify_auth_token(token):
         jwetoken = jwe.JWE()
         jwetoken.deserialize(token)
         jwetoken.decrypt(key)
         data = jwetoken.payload.decode('utf-8')
         data = json.loads(data)
         return data

@app.route('/')
def index():
    return 'welcome. api located at /api'

@app.route('/auth')
def get_auth_token():
    try:
        auth = request.authorization
        ts3conn = ts3.query.TS3ServerConnection(request.headers['ip']) # connect to teamspeak server
        try:
            print('logging in')
            ts3conn.exec_('login', client_login_name=auth.username, client_login_password=auth.password) # login to ts and check if valid
            ts3conn.close()
            token = User.generate_auth_token(auth.username, auth.password, request.headers['ip']) # passes on username, password and server ip
            return token # returns token

        except ts3.query.TS3QueryError as err:# shows error message if login fails
            ts3conn.close()
            return { 'error': err.resp.error['msg'] }, status.HTTP_401_UNAUTHORIZED

    except ts3.query.TS3TimeoutError as err:
        return { 'error': err.resp.error['msg'] }, status.HTTP_400_BAD_REQUEST

@auth.verify_token
def verify_token(token):
    print('verify')
    user = User.verify_auth_token(token)
    if not user:
        return False
    g.userdata = user
    return True

@app.route('/get/<command>')
@auth.login_required
def get(command):
    try:
        ts3conn = ts3.query.TS3ServerConnection(g.userdata['ip'])
        try:
            ts3conn.exec_('login', client_login_name=g.userdata['username'], client_login_password=g.userdata['password'])
            ts3conn.exec_('use', sid=request.headers['sid'])

        except ts3.query.TS3QueryError as err:
            return jsonify("Login failed:", err.resp.error["msg"])
            exit(1)

        try:
            query = ts3conn.exec_(command)
        except AttributeError:
            ts3conn.close()
            return jsonify({'message': 'Command not found: {0}' .format(command) })
        else:
            res = query
            ts3conn.close()
            return jsonify(res.parsed)

    except ts3.query.TS3TimeoutError as err:
        print('Connection to server failed:', err.resp.error['msg'])
        return jsonify({'error': 'Connection to server failed. Check if IP is correct'})

@app.route('/post/<command>', methods=['POST'])
@auth.login_required
def post(command):
    try:
        ts3conn = ts3.query.TS3ServerConnection(g.userdata['ip'])
        req = request.get_json()
        try:
            ts3conn.exec_('login', client_login_name=g.userdata['username'], client_login_password=g.userdata['password'])
            ts3conn.exec_('use', sid=request.headers['sid'])

        except ts3.query.TS3QueryError as err:
            return jsonify("Login failed:", err.resp.error["msg"])
            exit(1)

        try:
            query = ts3conn.exec_(command, **req)
        except AttributeError:
            ts3conn.close()
            return jsonify({'message': 'Command not found: {0}' .format(command) })
        else:
            res = query
            ts3conn.close()
            return jsonify(res.parsed)

    except ts3.query.TS3TimeoutError as err:
        print('Connection to server failed:', err.resp.error['msg'])
        return jsonify({'error': 'Connection to server failed. Check if IP is correct'})

if __name__ == '__main__':
    app.run(debug=True)
