#!/usr/bin/env python3
"""Pull the pending series of a patchwork project into a pinned snapshot.

Writes into OUT_DIR:
  series.json     every pending series seen (all dates), with msgid + lore URL
  candidates.tsv  latest version per series, filtered by --since and --exclude-author
  mbox/<id>.mbox  the exact mbox of each candidate (pinned input)
  meta/<id>.json  patchwork series detail (cover letter, patch ids)

Usage:
  pw_intake.py OUT_DIR [--project 405] [--list mptcp] [--since 2026-07-01]
               [--exclude-author "Name A" --exclude-author "Name B"]
               [--states new,under-review,changes-requested,needs-ack]

Run with `python3 -I`. Network: patchwork.kernel.org REST API only (lore's HTML
is bot-blocked; the API and b4 are not).
"""
import argparse, collections, json, os, re, sys, time, urllib.error, urllib.request

API = "https://patchwork.kernel.org/api/1.3"


def get(url, retries=3):
    for i in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:  # patchwork answers a page past the end with 404
                return None
            if i == retries - 1:
                raise
            print(f"retry {url}: {e}", file=sys.stderr)
            time.sleep(5 * (i + 1))
        except Exception as e:  # network drops are common here; retry
            if i == retries - 1:
                raise
            print(f"retry {url}: {e}", file=sys.stderr)
            time.sleep(5 * (i + 1))
    raise RuntimeError(f"unreachable: {url}")


def norm(name):
    # "[mptcp-net,v3] mptcp: foo" -> "mptcp: foo"; used to group versions
    return re.sub(r"^\[[^\]]*\]\s*", "", name).strip().lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--project", default="405")
    ap.add_argument("--list", default="mptcp", help="lore list name for links")
    ap.add_argument("--since", default="")
    ap.add_argument("--exclude-author", action="append", default=[])
    ap.add_argument("--states", default="new,under-review,changes-requested,needs-ack")
    a = ap.parse_args()
    os.makedirs(f"{a.out}/mbox", exist_ok=True)
    os.makedirs(f"{a.out}/meta", exist_ok=True)

    ser = {}
    for st in a.states.split(","):
        page = 1
        while True:
            raw = get(f"{API}/patches/?project={a.project}&state={st}&per_page=100&page={page}")
            if raw is None:
                break
            try:
                patches = json.loads(raw)
            except ValueError:
                break
            if not isinstance(patches, list) or not patches:
                break
            for p in patches:
                for s in p.get("series") or []:
                    e = ser.setdefault(str(s["id"]), dict(
                        name=s["name"], version=s.get("version") or 1,
                        submitter=p["submitter"]["name"], email=p["submitter"]["email"],
                        date=p["date"][:10], states=collections.Counter(), n=0,
                        first_msgid=None))
                    e["states"][p["state"]] += 1
                    e["n"] += 1
                    e["date"] = max(e["date"], p["date"][:10])
                    e["first_msgid"] = e["first_msgid"] or p["msgid"].strip("<>")
            page += 1

    # latest version per series name, after date/author filters
    best = {}
    for sid, v in ser.items():
        if a.since and v["date"] < a.since:
            continue
        if any(x.lower() in (v["submitter"] + " " + v["email"]).lower() for x in a.exclude_author):
            continue
        key = (v["version"], v["date"])
        n = norm(v["name"])
        if n not in best or key > best[n][0]:
            best[n] = (key, sid)

    rows = []
    for _, sid in sorted(best.values(), key=lambda kv: kv[0][1], reverse=True):
        meta = f"{a.out}/meta/{sid}.json"
        if not os.path.exists(meta):
            open(meta, "wb").write(get(f"{API}/series/{sid}/") or b"{}")
        s = json.load(open(meta))
        msgid = ((s.get("cover_letter") or {}).get("msgid") or s["patches"][0]["msgid"]).strip("<>")
        ser[sid]["msgid"] = msgid
        ser[sid]["lore"] = f"https://lore.kernel.org/{a.list}/{msgid}/"
        mb = f"{a.out}/mbox/{sid}.mbox"
        if not os.path.exists(mb):
            open(mb, "wb").write(get(f"https://patchwork.kernel.org/series/{sid}/mbox/") or b"")
        v = ser[sid]
        rows.append([sid, f"v{v['version']}", str(v["n"]), v["date"], v["submitter"],
                     v["name"], msgid, v["lore"]])

    json.dump({k: dict(v, states=dict(v["states"])) for k, v in ser.items()},
              open(f"{a.out}/series.json", "w"), indent=1)
    with open(f"{a.out}/candidates.tsv", "w") as f:
        f.write("id\tver\tpatches\tdate\tauthor\ttitle\tmsgid\tlore\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    old = sum(1 for v in ser.values() if a.since and v["date"] < a.since)
    print(f"{len(ser)} pending series; {len(rows)} candidates after filters; "
          f"{old} older than --since (check them with staleness.py, do not ignore silently)")


if __name__ == "__main__":
    main()
