#!/usr/bin/env python3
"""Is a pending series still alive, or concluded some other way?

For each series id: last on-list activity (patchwork comments on its patches),
and commits in the merged trees, since the series was posted, that (a) credit
its author in a trailer (Reported-by/Suggested-by/Co-developed-by/Tested-by) or
(b) share its subject. (a) is the "maintainer reworked it and credited the
author" pattern: a series can look pending forever after it was concluded.

Usage:
  staleness.py <intake-dir> <kernel-repo> <ref> [<ref>...] --ids 1129243,1157668
       [--paths net/mptcp,include/net/mptcp.h] [--stale-days 60]

Output is evidence, not a verdict: a credit hit can be an unrelated review
trailer, so read the commit before calling a series concluded. Patchwork's
per-patch comment API does not include replies to a cover letter; check lore
before calling a series "no replies".
"""
import argparse, datetime, json, os, re, subprocess, urllib.request

API = "https://patchwork.kernel.org/api/1.3"


def get_json(url, cache):
    if not os.path.exists(cache):
        with urllib.request.urlopen(url, timeout=60) as r:
            open(cache, "wb").write(r.read())
    try:
        return json.load(open(cache))
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("intake")
    ap.add_argument("repo")
    ap.add_argument("refs", nargs="+")
    ap.add_argument("--ids", required=True)
    ap.add_argument("--paths", default="net/mptcp,include/net/mptcp.h")
    ap.add_argument("--stale-days", type=int, default=60)
    a = ap.parse_args()
    os.makedirs(f"{a.intake}/meta/comments", exist_ok=True)
    today = datetime.date.today()
    print("id\tposted\tlast_activity\tby\tdays_quiet\tflag\tcredit_or_subject_hits\ttitle")
    for sid in a.ids.split(","):
        s = get_json(f"{API}/series/{sid}/", f"{a.intake}/meta/{sid}.json")
        if not s:
            print(f"{sid}\t?\t?\t?\t?\tFETCH-FAILED\t\t")
            continue
        posted, author = s["date"][:10], s["submitter"]["name"]
        last, by = posted, author
        for p in s["patches"]:
            C = get_json(f"{API}/patches/{p['id']}/comments/",
                         f"{a.intake}/meta/comments/{p['id']}.json") or []
            for c in C if isinstance(C, list) else []:
                if c["date"][:10] > last:
                    last, by = c["date"][:10], (c.get("submitter") or {}).get("name") or "?"
        quiet = (today - datetime.date.fromisoformat(last)).days
        flag = "STALE" if quiet > a.stale_days else "live"
        subj = s["patches"][0]["name"].split("] ", 1)[-1]
        # Reworked fixes rarely keep the title; the function names they touch
        # usually survive ("fix KMSAN: uninit-value in mptcp_established_options"
        # was merged as "fix uninit-value in mptcp_established_options").
        idents = [w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]+", subj) if "_" in w]
        git = ["git", "-C", a.repo, "log", f"--since={posted}", "--format=%h %an: %s"]
        tail = a.refs + ["--"] + a.paths.split(",")
        out = subprocess.run(git + [
            f"--grep=\\(Reported\\|Suggested\\|Co-developed\\)-by: {author}"] + tail,
            capture_output=True, text=True).stdout
        for needle in [subj[:50]] + idents:
            out += subprocess.run(git + ["-F", f"--grep={needle}"] + tail,
                                  capture_output=True, text=True).stdout
        hits = {l for l in out.splitlines() if l and not l.split(" ", 1)[1].startswith(author)}
        print(f"{sid}\t{posted}\t{last}\t{by}\t{quiet}\t{flag}\t{' ; '.join(sorted(hits))[:600]}\t{s['name'][:70]}")


if __name__ == "__main__":
    main()
