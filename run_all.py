#!/usr/bin/env python3
"""Regenerates every number, table and figure of the paper from the shipped matrices.
Works on Windows, Linux and macOS:   python run_all.py
"""
import os, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "outputs")
os.makedirs(OUT, exist_ok=True)
STEPS = [("audit_corpus.py", "audit_corpus.txt"), ("worked_month.py", "worked_month.txt"),
         ("run_published.py", "published.txt"), ("fig_dataset.py", None),
         ("fig_ics.py", None), ("fig_corpus.py", None)]

env = dict(os.environ, PYTHONIOENCODING="utf-8", MPLBACKEND="Agg")
for script, log in STEPS:
    print("=== %s" % script, flush=True)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", script)], cwd=ROOT, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    print(r.stdout, flush=True)
    if log:
        with open(os.path.join(OUT, log), "w", encoding="utf-8") as fh:
            fh.write(r.stdout)
    if r.returncode != 0:
        sys.exit("FAILED: %s (exit code %d)" % (script, r.returncode))

if shutil.which("pdflatex"):
    subprocess.run(["pdflatex", "-interaction=batchmode", "fig_flow.tex"],
                   cwd=os.path.join(ROOT, "figures"), stdout=subprocess.DEVNULL)
    for ext in (".aux", ".log"):
        p = os.path.join(ROOT, "figures", "fig_flow" + ext)
        if os.path.exists(p):
            os.remove(p)
else:
    print("pdflatex not found: fig_flow.pdf left as shipped")
print("\nDone. Results are in outputs\\ and figures\\" if os.name == "nt" else "\nDone. Results are in outputs/ and figures/")
