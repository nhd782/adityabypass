import hashlib, time, uuid

from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity,
)
from functools import wraps
from pymongo import MongoClient


app = Flask("")
jwt = JWTManager(app)

# can confirm this is random, gotten with a fair rolled dice
app.config[
    "JWT_SECRET_KEY"
] = '#^\x04<\x90\tH^\x83\x05\xa2\x88\xfe8s\xad\x9e_\xd6\x82I\xed\xe4\xdf\xb9\x92\x80\xcc\x8d:\xf0\xe7\xb3|\x16Ssy\xd4\x01\x0b"\x0e;nc\xb1\xbb\xd0\xe1\xd0\\@\x11e\xa3\xbb\xb3\x1b\x83\x99\xde\x8d}'

client = MongoClient("mongodb+srv://aditya:aditya@aditya.fbrbuw4.mongodb.net")
db = client.aditya
collection = db.aditya
paymentkeys = db.paymentkeys


def get_ip():
    headers = [
        "CF-Connecting-IP",  # Cloudflare
        "True-Client-IP",  # Akamai
        "X-Real-IP",  # Nginx proxy/Fastly
        "X-Forwarded-For",  # Most proxies
        "X-Cluster-Client-IP",  # Rackspace Cloud Load Balancer, Riverbed's Stingray
    ]
    for header in headers:
        if request.headers.get(header):
            return request.headers[header].split(",")[0].strip()
    return request.remote_addr


def rate_limit(max_per_minute):
    interval = 60.0 / float(max_per_minute)

    def decorator(f):
        times = {}

        @wraps(f)
        def wrapped_f(*args, **kwargs):
            ip = get_ip()
            now = time.time()
            if ip not in times:
                times[ip] = [now]
            else:
                while times[ip] and now - times[ip][-1] > interval:
                    times[ip].pop()
                times[ip].append(now)
                if len(times[ip]) > max_per_minute:
                    return jsonify({"message": "𝙏𝙤𝙤 𝙈𝙖𝙣𝙮 𝙍𝙚𝙦𝙪𝙚𝙨𝙩𝙨❗"}), 429
            return f(*args, **kwargs)

        return wrapped_f

    return decorator


@app.route("/api/register", methods=["POST"])
@rate_limit(5)
def register():
    if not request.is_json:
        return jsonify({"message": "𝙉𝙤 𝙅𝙎𝙊𝙉 𝙍𝙚𝙘𝙚𝙞𝙫𝙚𝙙❗"}), 400

    data = request.get_json()
    fingerprint = data.get("fingerprint")
    if not fingerprint:
        return jsonify({"message": "𝙄𝙣𝙫𝙖𝙡𝙞𝙙 𝙁𝙞𝙣𝙜𝙚𝙧𝙥𝙧𝙞𝙣𝙩❗"}), 400

    username = data.get("username")
    passkeys = data.get("password")
    if collection.find_one({"username": username}):
        return jsonify({"message": "𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚 𝘼𝙡𝙧𝙚𝙖𝙙𝙮 𝙀𝙭𝙞𝙨𝙩𝙨❗"}), 400

    paymentkey = data.get("payment_key")
    password = hashlib.sha256(data.get("password").encode("utf-8")).hexdigest()

    new_user = {
        "username": username,
        "passkeys": passkeys,
        "password": password,
        "fingerprint": [fingerprint],
        "ip": get_ip(),
        "settings": {
            "bin": "",
            "proxy": "",
            "logs": ["yellow:yellow:Welcome To NAHID BYPASS !!"],
        },
        "role": "stable",
        "invites": {},
    }
    collection.insert_one(new_user)

    return jsonify({"message": "𝙐𝙨𝙚𝙧 𝙍𝙚𝙜𝙞𝙨𝙩𝙚𝙧𝙚𝙙 𝙎𝙪𝙘𝙘𝙚𝙨𝙛𝙪𝙡𝙡𝙮, 𝙉𝙤𝙬 𝙇𝙤𝙜𝙞𝙣"}), 200


@app.route("/api/login", methods=["POST"])
@rate_limit(5)
def login():
    if not request.is_json:
        return jsonify({"message": "No JSON received"}), 400

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = collection.find_one({"username": username})

    if (
        user
        and user["password"] == hashlib.sha256(password.encode("utf-8")).hexdigest()
    ):
        fingerprint = data.get("fingerprint")
        if not fingerprint or int(fingerprint) not in user["fingerprint"]:
            return jsonify({"message": "𝙄𝙣𝙫𝙖𝙡𝙞𝙙 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚 𝙊𝙧 𝙋𝙖𝙨𝙨𝙬𝙤𝙧𝙙 !!"}), 401

        ip = get_ip()
        collection.update_one({"_id": user["_id"]}, {"$set": {"ip": ip}})

        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "𝙄𝙣𝙫𝙖𝙡𝙞𝙙 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚 𝙊𝙧 𝙋𝙖𝙨𝙨𝙬𝙤𝙧𝙙 !!"}), 401


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def get_site(path):
    if path == "register":
        path = "register/index.html"
    elif path == "login":
        path = "login/index.html"
    elif path == "panel":
        path = "panel/index.html"
    elif path == "":
        path = "index.html"
    return send_from_directory("site", path)


app.run(host="0.0.0.0", port=80)
