#!/usr/bin/env python3
"""The five published decision problems (Section 5.4, Table 7).

    python scripts/run_published.py
"""
import os, glob, json
import numpy as np
from _common import PUBLISHED, OUT
from normaudit import audit, load_matrix_csv
from normaudit.methods import (saw_minmax, topsis, topsis_minmax, inverted_pairs,
                               kendall_tau_b, same_top)

res = {}
print("%-32s %6s %5s %6s %-14s %8s %4s %4s %7s %7s" % (
    "problem", "n x m", "nu", "dw", "largest shift", "flagged", "T", "c", "tau_T", "tau_c"))
for f in sorted(glob.glob(os.path.join(PUBLISHED, "*.csv"))):
    p = load_matrix_csv(f)
    n, m = p.X.shape
    a = audit(p.X, p.o, p.w)
    wc = p.w / a.kappa
    wc = wc / wc.sum()
    s = saw_minmax(p.X, p.o, p.w)
    t = topsis(p.X, p.o, p.w)
    tc = topsis(p.X, p.o, wc)
    tm = topsis_minmax(p.X, p.o, p.w)
    fl = set(map(tuple, a.flagged_pairs))
    j = int(np.argmax(np.abs(a.shift_pp)))
    r = dict(n=n, m=m, nu=float(a.nu), dw=float(a.delta_w),
             shift_criterion=p.criteria[j], shift_pp=float(a.shift_pp[j]),
             flagged=len(fl), pairs=n * (n - 1) // 2,
             inv_topsis=len(inverted_pairs(s, t)), inv_comp=len(inverted_pairs(s, tc)),
             tau_topsis=float(kendall_tau_b(s, t)), tau_comp=float(kendall_tau_b(s, tc)),
             same_top_topsis=bool(same_top(s, t)), same_top_comp=bool(same_top(s, tc)),
             top_additive=p.alternatives[int(np.argmax(s))],
             top_topsis=p.alternatives[int(np.argmax(t))],
             top_comp=p.alternatives[int(np.argmax(tc))],
             prop1_maxdiff=float(np.max(np.abs(tc - tm))),
             kappa=[float(k) for k in a.kappa], w=[float(x) for x in p.w],
             w_eff=[float(x) for x in a.w_eff], w_star=[float(x) for x in wc])
    name = os.path.basename(f)[:-4]
    res[name] = r
    print("%-32s %2dx%-3d %5.1f %6.3f %-8s %+5.1f %4d/%-3d %4d %4d %7.3f %7.3f" % (
        name, n, m, r["nu"], r["dw"], r["shift_criterion"][:8], r["shift_pp"], r["flagged"],
        r["pairs"], r["inv_topsis"], r["inv_comp"], r["tau_topsis"], r["tau_comp"]))
json.dump(res, open(os.path.join(OUT, "published_results.json"), "w"), indent=1)
print("\nProposition 1 check, max |CC_vec(w*) - CC_mm(w)|: %.1e"
      % max(r["prop1_maxdiff"] for r in res.values()))
print("wrote outputs/published_results.json")
