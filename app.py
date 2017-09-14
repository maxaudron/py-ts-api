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

# Config
app.config['SECRET_KEY'] = 'a long secret to encrypt user data' # Secret used for generation of auth token PLEASE CHANGE

class User():
    # ...

    def generate_auth_token(userdata, ip, expiration = 6000):
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'username': userdata['username'], 'password': userdata['password'], 'ip': ip }) # creates token

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)  # decrypts the token
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        return data

@app.route('/api/auth')
@auth.login_required
def get_auth_token():
    token = User.generate_auth_token(g.userdata, request.headers['ip']) # passes on username, password and server ip
    return jsonify({ 'token': token.decode('ascii') }) # returns token

@auth.verify_password
def verify_password(username, password):
    if request.path == '/api/auth':              # if user requests token use password auth
        print('generating token')
        with ts3.query.TS3Connection(request.headers['ip']) as ts3conn: # connect to teamspeak server
            try:
                ts3conn.login(client_login_name=username, client_login_password=password) # login to ts and check if valid
                g.userdata = {'username': username, 'password': password}
                return True

            except ts3.query.TS3QueryError as err:# shows error message if login fails
                print("Login failed:", err.resp.error["msg"])
                return False
            print("Error:", resp.error["id"], resp.error["msg"])
    else:
        user = User.verify_auth_token(username)
        if not user:
            return False
    g.userdata = user
    return True

@app.route('/api/get/<command>')
@auth.login_required
def get(command):
    with ts3.query.TS3Connection(g.userdata['ip']) as ts3conn:
        try:
            ts3conn.login(client_login_name=g.userdata['username'], client_login_password=g.userdata['password'])

        except ts3.query.TS3QueryError as err:
            return jsonify("Login failed:", err.resp.error["msg"])
            exit(1)

        ts3conn.use(sid=request.headers['sid'])
        try:
            func = getattr(ts3conn, command)
        except AttributeError:
            return jsonify({'message': 'Command not found: {0}' .format(command) })
        else:
            res = func()
        return jsonify(res.parsed)

@app.route('/api/post/<command>', methods=['POST'])
@auth.login_required
def post(command):
    with ts3.query.TS3Connection(g.userdata['ip']) as ts3conn:
        print(request.get_json())
        req = request.get_json()
        try:
            ts3conn.login(client_login_name=g.userdata['username'], client_login_password=g.userdata['password'])

        except ts3.query.TS3QueryError as err:
            return jsonify("Login failed:", err.resp.error["msg"])
            exit(1)

        ts3conn.use(sid=request.headers['sid'])
        try:
            func = getattr(ts3conn, command)
        except AttributeError:
            return jsonify({'message': 'Command not found: {0}' .format(command) })
        else:
            res = func(**req)
        return jsonify(res.parsed)

if __name__ == '__main__':
    app.run(debug=True)
