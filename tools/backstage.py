#!/usr/bin/env python3
"""Backstage of SphärenKlänge: unreleased songs, stored encrypted in the public repo.

Only someone with the password can read the list, the covers or the songs.
  backstage/schluessel.json  password -> content key (PBKDF2-SHA256 + AES-GCM key wrap)
  backstage/liste.bin        encrypted list (JSON): {"albums": [{id, title, cover}], "tracks": [...]}
                             a track with "album": <album id> belongs to that album
  backstage/<random>.bin     encrypted MP3s and covers
Every .bin file is: 12-byte nonce + AES-256-GCM ciphertext (with tag).

Usage (password from the environment variable BACKSTAGE_PW):
  backstage.py init                       new, empty backstage with this password
  backstage.py passwd NEW_PASSWORD        change the password (songs stay as they are)
  backstage.py list
  backstage.py add MP3 TITLE COVER [--lyrics FILE] [--note TEXT] [--id ID] [--album ALBUM_ID]
  backstage.py album-add ALBUM_ID TITLE COVER     new album (its songs are added with --album)
  backstage.py album-remove ALBUM_ID              album and all its songs
  backstage.py album-text ALBUM_ID TEXT           short text by Baldur above the songs ("" removes it)
  backstage.py remove ID
  backstage.py export ID OUT.mp3 [OUT_COVER.jpg]   decrypt a song again (to publish it)
"""
import base64, json, os, secrets, subprocess, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backstage")
KEYFILE, LIST = os.path.join(ROOT, "schluessel.json"), os.path.join(ROOT, "liste.bin")
ITER = 600_000
b64 = lambda b: base64.b64encode(b).decode()


def wrap_key(pw, key):
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    kek = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(pw.encode())
    return {"v": 1, "iter": ITER, "salt": b64(salt), "iv": b64(iv), "key": b64(AESGCM(kek).encrypt(iv, key, None))}


def content_key(pw):
    k = json.load(open(KEYFILE))
    kek = PBKDF2HMAC(hashes.SHA256(), 32, base64.b64decode(k["salt"]), k["iter"]).derive(pw.encode())
    return AESGCM(kek).decrypt(base64.b64decode(k["iv"]), base64.b64decode(k["key"]), None)


def enc(key, data):
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, data, None)


def dec(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def load_list(key):
    d = json.loads(dec(key, open(LIST, "rb").read())) if os.path.exists(LIST) else []
    return d if isinstance(d, dict) else {"albums": [], "tracks": d}


def save_list(key, data):
    open(LIST, "wb").write(enc(key, json.dumps(data, ensure_ascii=False).encode()))


def drop_files(*paths):
    for f in paths:
        p = os.path.join(ROOT, os.path.basename(f))
        if os.path.exists(p):
            os.remove(p)


def rnd_name():
    return secrets.token_hex(8) + ".bin"


def main():
    a = sys.argv[1:]
    pw = os.environ.get("BACKSTAGE_PW", "")
    if not a or not pw:
        sys.exit(__doc__)
    cmd = a[0]
    os.makedirs(ROOT, exist_ok=True)
    if cmd == "init":
        key = secrets.token_bytes(32)
        json.dump(wrap_key(pw, key), open(KEYFILE, "w"), indent=1)
        save_list(key, {"albums": [], "tracks": []})
        return print("Backstage angelegt.")
    key = content_key(pw)
    data = load_list(key)
    items = data["tracks"]
    if cmd == "passwd":
        json.dump(wrap_key(a[1], key), open(KEYFILE, "w"), indent=1)
        print("Passwort geändert.")
    elif cmd == "list":
        for al in data["albums"]:
            print("ALBUM", al["id"], "|", al["title"])
        for t in items:
            print(t["id"], "|", t["title"], "|", t.get("album", "-"), "|", t.get("note", ""), "|", t["file"])
    elif cmd == "album-add":
        fc = rnd_name()
        open(os.path.join(ROOT, fc), "wb").write(enc(key, open(a[3], "rb").read()))
        data["albums"].append({"id": a[1], "title": a[2], "cover": "backstage/" + fc})
        save_list(key, data)
        print("Album angelegt:", a[1], a[2])
    elif cmd == "album-text":
        for al in data["albums"]:
            if al["id"] == a[1]:
                if a[2]:
                    al["text"] = a[2]
                else:
                    al.pop("text", None)
        save_list(key, data)
        print("Text gesetzt.")
    elif cmd == "album-remove":
        for al in [x for x in data["albums"] if x["id"] == a[1]]:
            drop_files(al["cover"])
        for t in [x for x in items if x.get("album") == a[1]]:
            drop_files(t["file"], t["cover"])
        data = {"albums": [x for x in data["albums"] if x["id"] != a[1]], "tracks": [x for x in items if x.get("album") != a[1]]}
        save_list(key, data)
        print("Album entfernt.")
    elif cmd == "add":
        mp3, title, cover = a[1], a[2], a[3]
        opts = dict(zip(a[4::2], a[5::2]))
        dur = float(subprocess.run(["ffprobe", "-v", "quiet", "-show_entries", "format=duration", "-of", "csv=p=0", mp3],
                                   capture_output=True, text=True).stdout.strip())
        fa, fc = rnd_name(), rnd_name()
        open(os.path.join(ROOT, fa), "wb").write(enc(key, open(mp3, "rb").read()))
        open(os.path.join(ROOT, fc), "wb").write(enc(key, open(cover, "rb").read()))
        t = {"id": opts.get("--id", "bs" + secrets.token_hex(3)), "title": title, "dur": round(dur, 1),
             "size": os.path.getsize(mp3), "file": "backstage/" + fa, "cover": "backstage/" + fc}
        if "--lyrics" in opts:
            t["lyrics"] = open(opts["--lyrics"], encoding="utf-8").read().strip()
        if "--note" in opts:
            t["note"] = opts["--note"]
        if "--album" in opts:
            assert any(x["id"] == opts["--album"] for x in data["albums"]), "Album fehlt"
            t["album"] = opts["--album"]
        items.append(t)
        save_list(key, data)
        print("Hinzugefügt:", t["id"], title)
    elif cmd == "remove":
        keep = []
        for t in items:
            if t["id"] == a[1]:
                drop_files(t["file"], t["cover"])
            else:
                keep.append(t)
        data["tracks"] = keep
        save_list(key, data)
        print("Entfernt." if len(keep) < len(items) else "Nicht gefunden.")
    elif cmd == "export":
        t = next(x for x in items if x["id"] == a[1])
        open(a[2], "wb").write(dec(key, open(os.path.join(ROOT, os.path.basename(t["file"])), "rb").read()))
        if len(a) > 3:
            open(a[3], "wb").write(dec(key, open(os.path.join(ROOT, os.path.basename(t["cover"])), "rb").read()))
        print(json.dumps({k: v for k, v in t.items() if k != "lyrics"}, ensure_ascii=False))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
