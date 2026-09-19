#!/usr/bin/env python3
"""
Fetch the EPSS history needed for the ICS decision-matrix corpus.  (v2)

Reads ics_corpus/sources/ics_corpus_request.json, collects 33 daily EPSS releases, keeps only the
CVEs belonging to each month's matrix, and writes one small CSV.

    python scripts/fetch_epss_history.py

Options
    --cache DIR   keep/reuse the downloaded daily files in DIR
    --api         skip the bulk download and use the FIRST API instead
    --check       print what would be fetched, then exit

Standard library only. Output: epss_history_ics_corpus.csv (~200-400 KB).
Upload that one file; the daily downloads stay on your machine.

NOTE: do not open the request file or the output in Excel before sending them.
Excel rewrites ISO dates such as 2024-01-31 into local formats like 31-01-2024,
which breaks the download URLs.  The request file is JSON for that reason.
"""

import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ics_corpus", "sources")
REQUEST_JSON = os.path.join(HERE, "ics_corpus_request.json")
REQUEST_CSV = os.path.join(HERE, "ics_corpus_cves.csv")
OUT = os.path.join(HERE, "epss_history_ics_corpus.csv")

# epss.cyentia.com now redirects here; both are tried.
HOSTS = ["https://epss.empiricalsecurity.com", "https://epss.cyentia.com"]
API = "https://api.first.org/data/v1/epss"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def iso_date(text):
    """Normalise a date that Excel may have rewritten. Returns YYYY-MM-DD."""
    text = (text or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return text
    m = re.fullmatch(r"(\d{1,2})[-/](\d{1,2})[-/](\d{4})", text)
    if m:                                   # DD-MM-YYYY or MM/DD/YYYY
        a, b, year = int(m.group(1)), int(m.group(2)), m.group(3)
        day, month = (a, b) if a > 12 else (b, a) if b > 12 else (a, b)
        return "%s-%02d-%02d" % (year, month, day)
    m = re.fullmatch(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text)
    if m:
        return "%s-%02d-%02d" % (m.group(1), int(m.group(2)), int(m.group(3)))
    raise ValueError("unrecognised date %r - was the file opened in Excel?" % text)


def load_request():
    """Return [(month, iso_date, [cve, ...]), ...]."""
    if os.path.exists(REQUEST_JSON):
        with open(REQUEST_JSON, encoding="utf-8") as fh:
            blob = json.load(fh)
        return [(mo, iso_date(v["epss_date"]), list(v["cves"]))
                for mo, v in sorted(blob["months"].items())]
    if os.path.exists(REQUEST_CSV):
        print("ics_corpus_request.json not found; falling back to the CSV.")
        groups = {}
        with open(REQUEST_CSV, newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                key = row["month"]
                groups.setdefault(key, [iso_date(row["epss_date"]), []])[1].append(row["cve"])
        return [(mo, v[0], v[1]) for mo, v in sorted(groups.items())]
    sys.exit("ERROR: neither ics_corpus_request.json nor ics_corpus_cves.csv "
             "was found next to this script.")


def get(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def from_bulk(date, cache):
    """{cve: (epss, percentile)} from the daily release file."""
    name = "epss_scores-%s.csv.gz" % date
    if cache:
        gz = os.path.join(cache, name)
        plain = os.path.join(cache, name[:-3])
        if os.path.exists(plain):
            raw = open(plain, "rb").read()
            return parse(raw)
        if os.path.exists(gz):
            return parse(gzip.decompress(open(gz, "rb").read()))

    last = None
    for host in HOSTS:
        url = "%s/%s" % (host, name)
        try:
            blob = get(url)
        except Exception as exc:                       # noqa: BLE001
            last = "%s -> %s" % (url, exc)
            continue
        if cache:
            os.makedirs(cache, exist_ok=True)
            with open(os.path.join(cache, name), "wb") as fh:
                fh.write(blob)
        return parse(gzip.decompress(blob))
    raise RuntimeError(last or "download failed")


def parse(raw):
    scores = {}
    text = io.StringIO(raw.decode("utf-8", "replace"))
    first = text.readline()
    if not first.startswith("#"):
        text.seek(0)
    for row in csv.DictReader(text):
        cve = row.get("cve")
        if cve:
            scores[cve] = (row.get("epss", ""), row.get("percentile", ""))
    return scores


def from_api(date, cves):
    """{cve: (epss, percentile)} via the FIRST API, 100 CVEs per call."""
    scores = {}
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        url = "%s?date=%s&limit=100&cve=%s" % (API, date, ",".join(chunk))
        blob = json.loads(get(url, timeout=90).decode("utf-8"))
        for row in blob.get("data", []):
            scores[row["cve"]] = (row.get("epss", ""), row.get("percentile", ""))
        time.sleep(1.0)                                # be polite
    return scores


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default=None)
    ap.add_argument("--api", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    req = load_request()
    total = sum(len(c) for _, _, c in req)
    print("months: %d    CVE-month rows: %d" % (len(req), total))
    print("EPSS dates: %s ... %s" % (req[0][1], req[-1][1]))
    if args.check:
        for mo, date, cves in req:
            print("  %s  %s  %d CVEs" % (mo, date, len(cves)))
        print("\nfirst URL that would be tried:\n  %s/epss_scores-%s.csv.gz"
              % (HOSTS[0], req[0][1]))
        return 0

    rows, done = [], set()
    if os.path.exists(OUT):
        with open(OUT, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                rows.append(row)
                done.add(row["month"])
        if done:
            print("resuming: %d months already collected" % len(done))

    missing = 0
    failed = []
    for i, (mo, date, cves) in enumerate(req, 1):
        if mo in done:
            continue
        try:
            scores = (from_api(date, cves) if args.api
                      else from_bulk(date, args.cache))
        except Exception as exc:                       # noqa: BLE001
            print("  [%2d/%d] %s %s  FAILED: %s" % (i, len(req), mo, date, exc))
            if not args.api:
                print("         retrying this month through the FIRST API ...")
                try:
                    scores = from_api(date, cves)
                except Exception as exc2:              # noqa: BLE001
                    print("         API also failed: %s" % exc2)
                    failed.append(mo)
                    continue
            else:
                failed.append(mo)
                continue

        hit = 0
        for cve in cves:
            epss, pct = scores.get(cve, ("", ""))
            if epss:
                hit += 1
            else:
                missing += 1
            rows.append({"month": mo, "epss_date": date, "cve": cve,
                         "epss": epss, "percentile": pct})
        print("  [%2d/%d] %s %s  wanted %4d  found %4d"
              % (i, len(req), mo, date, len(cves), hit))

        with open(OUT, "w", newline="", encoding="utf-8") as fh:
            wr = csv.DictWriter(fh, ["month", "epss_date", "cve", "epss", "percentile"])
            wr.writeheader()
            wr.writerows(rows)

    if not rows:
        print("\nNothing collected. Run with --check to see the URLs, or "
              "--api to use the FIRST API instead of the bulk files.")
        return 1

    print("\nwrote %s  (%d rows, %.0f KB)"
          % (OUT, len(rows), os.path.getsize(OUT) / 1024.0))
    if missing:
        print("%d CVE-date lookups had no EPSS row (CVE newer than that "
              "release); left blank and dropped when the matrix is built." % missing)
    if failed:
        print("INCOMPLETE - these months failed: %s" % ", ".join(failed))
        print("Re-run the script; finished months are kept.")
    else:
        print("Complete. Upload epss_history_ics_corpus.csv only. "
              "Do not open it in Excel first.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
