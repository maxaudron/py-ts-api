#!/usr/bin/env python
from flask import Flask
from flask import jsonify
from flask import g
from flask import request
from flask_httpauth import HTTPBasicAuth

from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)


import ts3

app = Flask(__name__)
auth = HTTPBasicAuth()

class User():
    # ...

    def generate_auth_token(userdata, ip, expiration = 6000):
        s = Serializer('SECRET_KEY', expires_in = expiration)
        return s.dumps({ 'username': userdata['username'], 'password': userdata['password'], 'ip': ip })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer('SECRET_KEY')
        try:
            data = s.loads(token)
            print(data)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        return data

@app.route('/api/auth')
@auth.login_required
def get_auth_token():
    token = User.generate_auth_token(g.userdata, request.headers['ip'])
    return jsonify({ 'token': token.decode('ascii') })

@auth.verify_password
def verify_password(username, password):
    user = User.verify_auth_token(username)
    if not user:
        print('password auth')
        with ts3.query.TS3Connection(request.headers['ip']) as ts3conn:
            try:
                ts3conn.login(client_login_name=username, client_login_password=password) # login to ts and check if valid
                g.userdata = {'username': username, 'password': password}
                return True

            except ts3.query.TS3QueryError as err:
                print("Login failed:", err.resp.error["msg"])
                return False
    g.userdata = user
    return True

@app.route('/api/clientlist')
@auth.login_required
def index():
    with ts3.query.TS3Connection(g.userdata['ip']) as ts3conn:
        try:
            print(g.userdata['username'])
            print(g.userdata['password'])
            ts3conn.login(client_login_name=g.userdata['username'], client_login_password=g.userdata['password'])

        except ts3.query.TS3QueryError as err:
            print("Login failed:", err.resp.error["msg"])
            exit(1)

        ts3conn.use(sid=2)
        res = ts3conn.clientlist()
        print(res.parsed)
        return jsonify(res.parsed)

if __name__ == '__main__':
    app.run(debug=True)
