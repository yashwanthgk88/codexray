from flask import Flask, request
import os, subprocess, shlex, html
app = Flask(__name__)
cur = None

@app.route('/run')
def run():
    # UNDEFENDED: request.args into os.system
    cmd = request.args.get('ip')
    os.system('ping ' + cmd)
    return cmd

@app.route('/user')
def user():
    # UNDEFENDED: string-concatenated SQL
    uid = request.args.get('id')
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return uid

@app.route('/guarded')
def guarded():
    # GUARDED: shlex.quote before subprocess
    x = request.args.get('x')
    subprocess.call(shlex.quote(x), shell=True)
    return 'ok'

@app.route('/weak')
def weak():
    # WEAK: html.escape does not defend a SQL sink
    q = html.escape(request.args.get('q'))
    cur.execute("SELECT * FROM t WHERE a = '" + q + "'")
    return 'ok'

def not_reachable(x):
    return x.upper()

if __name__ == '__main__':
    app.run()
