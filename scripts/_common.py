"""Shared paths. Every script can be run from any directory."""
import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
CORPUS = os.path.join(ROOT, "ics_corpus")
MATRICES = os.path.join(CORPUS, "matrices")
SOURCES = os.path.join(CORPUS, "sources")
PUBLISHED = os.path.join(ROOT, "published_problems")
OUT = os.path.join(ROOT, "outputs")
FIG = os.path.join(ROOT, "figures")
for d in (OUT, FIG):
    os.makedirs(d, exist_ok=True)
CRITERIA = ["SSVC_Exploitation", "SSVC_Automatable", "SSVC_TechnicalImpact",
            "CVSS_Exploitability", "CVSS_Impact", "EPSS"]
