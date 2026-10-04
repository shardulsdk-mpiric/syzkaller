#!/usr/bin/env python3
"""Bucket kcov PCs ("pc <hex>" lines) into kernel functions using a
/proc/kallsyms dump taken from the SAME boot (handles KASLR) and report the
net/quic-relevant functions.  Usage: bucket.py kallsyms pcs.txt [prefix]"""
import bisect, sys, collections

ks = sys.argv[1]; pcs = sys.argv[2]
syms = []
for line in open(ks):
    parts = line.split()
    if len(parts) < 3: continue
    addr, typ, name = int(parts[0], 16), parts[1], parts[2]
    if typ.lower() not in ('t', 'w'): continue
    syms.append((addr, name))
syms.sort()
addrs = [a for a, _ in syms]

cnt = collections.Counter()
total = 0
for line in open(pcs):
    if not line.startswith('pc '): continue
    pc = int(line.split()[1], 16)
    i = bisect.bisect_right(addrs, pc) - 1
    if i < 0: continue
    cnt[syms[i][1]] += 1
    total += 1

print(f"total unique PCs: {total}; distinct functions: {len(cnt)}")
# SCTP-relevant function names (net/quic is all sctp_* / __sctp_*)
quic = {k: v for k, v in cnt.items() if 'quic' in k}
print(f"net/quic functions: {len(quic)}; sctp PCs: {sum(quic.values())}")
for k, v in sorted(quic.items(), key=lambda kv: -kv[1]):
    print(f"  {v:5d}  {k}")
