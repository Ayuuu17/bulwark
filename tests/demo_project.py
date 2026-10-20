"""Builds deliberately vulnerable demo uploads: a source .zip, an Android .apk and an iOS .ipa.

    python tests/demo_project.py OUT_DIR     # writes demo-project.zip, demo-app.apk, demo-app.ipa

Secrets are assembled from pieces so this file itself doesn't look like it leaks real keys. All values are fake.
"""

import io
import json
import plistlib
import struct
import sys
import zipfile
from pathlib import Path

FAKE_AWS_KEY = "AKIA" + "DEMO" + "FAKEKEY12345"
FAKE_STRIPE_KEY = "sk_" + "live_" + "DemoFakeKey0000000000000"

SOURCE_FILES = {
    "app.py": f'''import pickle, random, sqlite3, subprocess
import requests, yaml
from flask import Flask, request

app = Flask(__name__)
AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"


@app.route("/user")
def user():
    db = sqlite3.connect("app.db")
    uid = request.args.get("id")
    return str(db.execute(f"SELECT * FROM users WHERE id = {{uid}}").fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {{host}}", shell=True)


@app.route("/import", methods=["POST"])
def import_data():
    return str(pickle.loads(request.data))


@app.route("/settings", methods=["POST"])
def settings():
    return str(yaml.load(request.data))


@app.route("/invoices/<int:invoice_id>")
def invoice(invoice_id):
    db = sqlite3.connect("app.db")
    return str(db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone())


def new_reset_token():
    token = random.randint(100000, 999999)
    return token


def partner_prices():
    return requests.get("https://partner.example.net/prices", verify=False).json()


if __name__ == "__main__":
    app.run(debug=True)
''',
    "server.js": '''const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");
const app = express();

app.use(require("cors")({ origin: true, credentials: true }));

app.get("/search", async (req, res) => {
  const rows = await db.query(`SELECT * FROM products WHERE name = '${req.query.q}'`);
  res.send(rows);
});

app.get("/convert", (req, res) => {
  exec("convert " + req.query.file + " out.png", () => res.send("ok"));
});

app.get("/go", (req, res) => res.redirect(req.query.next));
app.get("/calc", (req, res) => res.send(String(eval(req.query.expr))));

const token = jwt.sign({ id: 1 }, "super-secret-signing-key");
const dbPassword = "Pr0d-db-pa55w0rd!";
''',
    "public/app.js": '''document.getElementById("greeting").innerHTML = location.hash.slice(1);
localStorage.setItem("authToken", window.token);
fetch("http://api.demo-shop.net/v1/cart");
''',
    "tests/test_app.py": 'assert eval("1 + 1") == 2  # test files are excluded from code rules\n',
    "android/app/src/main/AndroidManifest.xml": '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.shop">
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <provider android:name=".OrdersProvider" android:authorities="com.demo.shop.orders" android:exported="true" />
  </application>
</manifest>
''',
    "android/app/build.gradle": '''android {
    defaultConfig {
        minSdkVersion 21
    }
}
dependencies {
    implementation 'com.squareup.okhttp3:okhttp:3.12.0'
}
''',
    "android/app/src/main/java/com/demo/shop/Api.java": '''package com.demo.shop;
class Api {
    void save(android.content.Context ctx, String token) {
        ctx.getSharedPreferences("prefs", 0).edit().putString("auth_token", token).apply();
        android.util.Log.d("Api", "token=" + token);
    }
}
''',
    "ios/Runner/Info.plist": plistlib.dumps({
        "CFBundleExecutable": "Runner",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoshop"]}],
    }).decode(),
    "firestore.rules": '''rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
''',
    "Dockerfile": "FROM python:3.12\nENV DB_PASSWORD=hunter2hunter2\nCOPY . /app\nCMD [\"python\", \"/app/app.py\"]\n",
    ".env": f"STRIPE_SECRET_KEY={FAKE_STRIPE_KEY}\n",
    "requirements.txt": "flask==0.12.2\npyyaml==5.3\nrequests==2.19.0\n",
    "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "demo"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/jsonwebtoken": {"version": "8.5.1"},
    }}),
    "mobile/pubspec.lock": 'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "0.12.0"\n',
}


def build_source_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in SOURCE_FILES.items():
            zf.writestr(f"demo-shop-main/{path}", content)  # GitHub-style wrapper folder
    return buffer.getvalue()


# --- minimal Android binary XML encoder (enough to build a test APK manifest) ---

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def encode_axml(root: tuple) -> bytes:
    """root = (tag, {"android:attr": "value"}, [children...])."""
    strings: list[str] = []

    def idx(s: str) -> int:
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    idx(ANDROID_NS)
    body = b""

    def element(node):
        nonlocal body
        tag, attrs, children = node
        encoded = b""
        for key, value in attrs.items():
            ns = idx(ANDROID_NS) if key.startswith("android:") else 0xFFFFFFFF
            name = idx(key.split(":", 1)[-1])
            if value in ("true", "false"):
                encoded += struct.pack("<IIIHBBI", ns, name, 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if value == "true" else 0)
            else:
                encoded += struct.pack("<IIIHBBI", ns, name, idx(value), 8, 0, 0x03, idx(value))
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, idx(tag), 20, 20, len(attrs), 0, 0, 0)
        chunk = struct.pack("<II", 0, 0xFFFFFFFF) + ext + encoded
        body += struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk
        for child in children:
            element(child)
        body += struct.pack("<HHI", 0x0103, 16, 24) + struct.pack("<IIII", 0, 0xFFFFFFFF, 0xFFFFFFFF, idx(tag))

    element(root)
    data = b""
    offsets = []
    for s in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    data += b"\x00" * (-len(data) % 4)
    header_size = 28
    pool = struct.pack("<IIIII", len(strings), 0, 0, header_size + 4 * len(strings), 0)
    pool += struct.pack(f"<{len(strings)}I", *offsets) + data
    pool = struct.pack("<HHI", 0x0001, header_size, 8 + len(pool)) + pool
    content = pool + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


def build_apk() -> bytes:
    manifest = ("manifest", {"package": "com.demo.shop"}, [
        ("uses-sdk", {"android:minSdkVersion": "21"}, []),
        ("application", {"android:debuggable": "true", "android:usesCleartextTraffic": "true"}, [
            ("activity", {"android:name": ".MainActivity", "android:exported": "true"}, [
                ("intent-filter", {}, [
                    ("action", {"android:name": "android.intent.action.MAIN"}, []),
                    ("category", {"android:name": "android.intent.category.LAUNCHER"}, []),
                ]),
            ]),
            ("provider", {"android:name": ".OrdersProvider", "android:exported": "true"}, []),
        ]),
    ])
    dex = b"dex\n035\x00" + b"\x00" * 64 + FAKE_AWS_KEY.encode() + b"\x00" + b"http://api.demo-shop.net/v1\x00"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", encode_axml(manifest))
        zf.writestr("classes.dex", dex)
    return buffer.getvalue()


def build_ipa() -> bytes:
    info = plistlib.dumps({
        "CFBundleExecutable": "DemoShop",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }, fmt=plistlib.FMT_BINARY)
    binary = b"\xcf\xfa\xed\xfe" + b"\x00" * 64 + FAKE_STRIPE_KEY.encode() + b"\x00"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("Payload/DemoShop.app/Info.plist", info)
        zf.writestr("Payload/DemoShop.app/DemoShop", binary)
    return buffer.getvalue()


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    (out / "demo-project.zip").write_bytes(build_source_zip())
    (out / "demo-app.apk").write_bytes(build_apk())
    (out / "demo-app.ipa").write_bytes(build_ipa())
    print(f"Wrote demo-project.zip, demo-app.apk, demo-app.ipa to {out.resolve()}")
