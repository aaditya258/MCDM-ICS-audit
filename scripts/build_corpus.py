#!/usr/bin/env python3
"""
Rebuild the 33 monthly ICS decision matrices from the public feeds.

Needs local clones of two CISA repositories:
    git clone --depth 1 https://github.com/cisagov/CSAF
    git clone --depth 1 https://github.com/cisagov/vulnrichment
and the contemporaneous EPSS values in
    ics_corpus/sources/epss_history_ics_corpus.csv
(shipped with this package, or regenerate with fetch_epss_history.py).

    python scripts/build_corpus.py --csaf PATH/CSAF --vulnrichment PATH/vulnrichment

For every CISA ICS advisory (ICSA) first released between 2024-01 and 2026-09,
each CVE becomes one alternative in the matrix of that month if it has
  (a) a CVSS v3.x vector in the advisory,
  (b) a CISA SSVC record in Vulnrichment, and
  (c) an EPSS value published on the last day of that month.
CVEs failing any of the three are left out (complete-case). Nothing is imputed.

Criteria (all benefit type, larger = more urgent, equal weights 1/6):
  SSVC_Exploitation     none 0, poc 0.5, active 1
  SSVC_Automatable      no 0, yes 1
  SSVC_TechnicalImpact  partial 0, total 1
  CVSS_Exploitability   sub-score recomputed from the vector (0 to 3.9)
  CVSS_Impact           sub-score recomputed from the vector (0 to 6.0)
  EPSS                  probability on the last day of the month

Note: the CISA repositories keep changing (advisories get revised, SSVC records
get added), so a rebuild at a later date can differ a little from the shipped
matrices. The shipped matrices are the ones used in the paper.
"""
import argparse, collections, csv, glob, json, os
import numpy as np
from _common import MATRICES, SOURCES, CORPUS, CRITERIA

FIRST, LAST = "2024-01", "2026-09"
EX = {"none": 0.0, "poc": 0.5, "active": 1.0}
AU = {"no": 0.0, "yes": 1.0}
TI = {"partial": 0.0, "total": 1.0}


def cvss_subscores(vector):
    """CVSS v3.x exploitability and impact sub-scores from the vector string."""
    m = dict(p.split(":") for p in vector.split("/")[1:])
    changed = m["S"] == "C"
    pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
    e = (8.22 * {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
         * {"L": .77, "H": .44}[m["AC"]] * pr * {"N": .85, "R": .62}[m["UI"]])
    z = {"H": .56, "L": .22, "N": 0}
    iss = 1 - (1 - z[m["C"]]) * (1 - z[m["I"]]) * (1 - z[m["A"]])
    i = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
    return round(e, 1), round(max(i, 0), 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf", required=True, help="path to the cisagov/CSAF clone")
    ap.add_argument("--vulnrichment", required=True, help="path to the cisagov/vulnrichment clone")
    ap.add_argument("--out", default=MATRICES)
    a = ap.parse_args()

    epss = {}
    with open(os.path.join(SOURCES, "epss_history_ics_corpus.csv"), encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            if r["epss"].strip():
                epss[(r["month"], r["cve"])] = float(r["epss"])
    print("contemporaneous EPSS values:", len(epss))

    ssvc = {}
    for f in glob.glob(os.path.join(a.vulnrichment, "20*", "*", "CVE-*.json")):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for adp in d["containers"].get("adp", []):
            for met in adp.get("metrics", []):
                o = met.get("other", {})
                if o.get("type") == "ssvc":
                    ssvc[os.path.basename(f)[:-5]] = {k: v for opt in o["content"]["options"]
                                                      for k, v in opt.items()}
    print("SSVC records:", len(ssvc))

    best = {}
    for f in sorted(glob.glob(os.path.join(a.csaf, "csaf_files", "OT", "white", "20*", "icsa-*.json"))):
        d = json.load(open(f, encoding="utf-8"))
        tr = d["document"]["tracking"]
        mo = tr["initial_release_date"][:7]
        if not (FIRST <= mo <= LAST):
            continue
        for v in d.get("vulnerabilities", []):
            cve = v.get("cve")
            sc = [s["cvss_v3"] for s in v.get("scores", [])
                  if "cvss_v3" in s and "vectorString" in s["cvss_v3"]]
            if not cve or not sc or cve not in ssvc or (mo, cve) not in epss:
                continue
            c = max(sc, key=lambda x: x["baseScore"])
            if (mo, cve) in best and c["baseScore"] <= best[(mo, cve)]["base"]:
                continue
            e, i = cvss_subscores(c["vectorString"])
            s = ssvc[cve]
            best[(mo, cve)] = dict(
                base=c["baseScore"], vector=c["vectorString"], advisory=tr["id"],
                title=d["document"]["title"], ssvc=s,
                row=[EX[s["Exploitation"]], AU[s["Automatable"]], TI[s["Technical Impact"]],
                     e, i, epss[(mo, cve)]])

    by = collections.defaultdict(list)
    for (mo, cve), rec in best.items():
        by[mo].append((cve, rec))
    os.makedirs(a.out, exist_ok=True)
    meta, prov = {}, []
    for mo in sorted(by):
        rows = sorted(by[mo], key=lambda t: t[0])
        X = np.array([r["row"] for _, r in rows], float)
        with open(os.path.join(a.out, "ics_%s.csv" % mo.replace("-", "_")), "w", newline="") as fh:
            fh.write("alternative," + ",".join(CRITERIA) + "\n")
            fh.write("__orientation__,1,1,1,1,1,1\n")
            fh.write("__weight__," + ",".join(["0.166667"] * 6) + "\n")
            for cve, r in rows:
                fh.write(cve + "," + ",".join("%g" % v for v in r["row"]) + "\n")
        const = [CRITERIA[j] for j in range(6) if X[:, j].max() - X[:, j].min() <= 0]
        meta[mo] = dict(n=len(rows), constant_columns=const,
                        advisories=len({r["advisory"] for _, r in rows}))
        for cve, r in rows:
            prov.append([mo, cve, r["advisory"], r["title"], r["base"], r["vector"],
                         r["ssvc"]["Exploitation"], r["ssvc"]["Automatable"],
                         r["ssvc"]["Technical Impact"]])
    json.dump(meta, open(os.path.join(CORPUS, "metadata.json"), "w"), indent=1)
    with open(os.path.join(CORPUS, "provenance.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["month", "cve", "advisory", "advisory_title", "cvss_base", "cvss_vector",
                    "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact"])
        w.writerows(prov)
    print("matrices written:", len(by), " alternatives:", sum(v["n"] for v in meta.values()))
    bad = {m: v["constant_columns"] for m, v in meta.items() if v["constant_columns"]}
    print("months with a constant column:", bad if bad else "none")


if __name__ == "__main__":
    main()
