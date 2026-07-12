"""Deliberately-messy demo target for CodeXray. Do NOT deploy this."""
import os
import subprocess
import pickle
import sqlite3

from flask import Flask, request, send_file, render_template_string

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return run_ping(host)


def run_ping(host):
    # command injection: host flows straight into a shell
    return os.system("ping -c 1 " + host)


@app.route("/lookup", methods=["GET", "POST"])
def lookup():
    uid = request.values.get("uid")
    return query_user(uid)


def query_user(uid):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL injection: uid concatenated into the query
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return str(cursor.fetchall())


@app.route("/download")
def download():
    name = request.args.get("name")
    # path traversal: user-controlled file path
    return send_file("/var/data/" + name)


@app.route("/render")
def render():
    tpl = request.args.get("tpl")
    # server-side template injection
    return render_template_string(tpl)


@app.route("/restore", methods=["POST"])
def restore():
    blob = request.get_data()
    # insecure deserialization
    return handle_restore(blob)


def handle_restore(blob):
    obj = pickle.loads(blob)
    return dispatch(obj)


def dispatch(obj):
    # dynamic dispatch — a blind spot the X-ray cannot follow
    handler = getattr(obj, "action", None)
    if handler:
        return handler()
    return "no-op"


def unused_helper(x):
    # not reachable from any entry point
    return x * 2


if __name__ == "__main__":
    app.run(debug=True)
