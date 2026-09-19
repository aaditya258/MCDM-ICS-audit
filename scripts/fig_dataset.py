#!/usr/bin/env python3
"""Figure describing the ICS corpus: size per month, SSVC levels, CVSS sub-scores, EPSS."""
import os, glob, csv, collections
import numpy as np, matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from _common import MATRICES, SOURCES, FIG
from normaudit import load_matrix_csv

months, n, X = [], [], []
for f in sorted(glob.glob(os.path.join(MATRICES, 'ics_*.csv'))):
    p = load_matrix_csv(f); months.append(os.path.basename(f)[4:11].replace('_', '-'))
    n.append(len(p.X)); X.append(p.X)
X = np.vstack(X); n = np.array(n)
req = collections.Counter()
with open(os.path.join(SOURCES, 'epss_history_ics_corpus.csv'), encoding='utf-8-sig') as fh:
    for r in csv.DictReader(fh): req[r['month']] += 1
left = np.array([req[m] for m in months]) - n

plt.rcParams.update({'font.size': 8, 'font.family': 'serif'})
fig, ax = plt.subplots(2, 2, figsize=(7.1, 4.9))
a = ax[0, 0]; x = np.arange(len(months))
a.bar(x, n, color='0.35', edgecolor='k', lw=.4, label='in the matrix')
a.bar(x, left, bottom=n, facecolor='white', edgecolor='k', lw=.4, hatch='////', label='left out, no EPSS value yet')
tk = [i for i, m in enumerate(months) if m[5:] in ('01', '07')]
a.set_xticks(tk); a.set_xticklabels([months[i] for i in tk], fontsize=6.8)
a.set_ylabel('vulnerabilities in the month'); a.set_ylim(0, 680); a.legend(frameon=False, fontsize=6.6, loc='upper left')
a.set_title('(a)', loc='left', fontsize=8.5)

a = ax[0, 1]
rows = [('Exploitation', X[:, 0], [(0, 'none'), (.5, 'proof of concept'), (1, 'active')]),
        ('Automatable', X[:, 1], [(0, 'no'), (1, 'yes')]),
        ('Technical\nImpact', X[:, 2], [(0, 'partial'), (1, 'total')])]
shade = ['white', '0.7', '0.25']
for k, (nm, col, lv) in enumerate(rows):
    l0 = 0
    for q, (v, lab) in enumerate(lv):
        sh = 100 * np.mean(col == v); c = shade[q] if len(lv) == 3 else shade[2 * q]
        a.barh(k, sh, left=l0, color=c, edgecolor='k', lw=.5, height=.55)
        if sh > 9: a.text(l0 + sh / 2, k, '%s\n%.0f%%' % (lab, sh), ha='center', va='center', fontsize=6.4, color='white' if c == '0.25' else 'k')
        l0 += sh
e = X[:, 0]
a.text(100, -.52, 'proof of concept %.1f%%, active %.1f%%' % (100 * np.mean(e == .5), 100 * np.mean(e == 1)), ha='right', fontsize=6.2)
a.set_yticks(range(3)); a.set_yticklabels([r[0] for r in rows], fontsize=7); a.invert_yaxis()
a.set_xlim(0, 100); a.set_ylim(2.5, -.8); a.set_xlabel('share of the 4023 vulnerabilities (%)'); a.set_title('(b)  SSVC decision points', loc='left', fontsize=8.5)

a = ax[1, 0]
b = np.arange(0, 6.3, .3)
a.hist(X[:, 4], bins=b, color='0.35', edgecolor='k', lw=.4, label='impact (max 6.0)')
a.hist(X[:, 3], bins=b, histtype='step', color='k', lw=1.3, ls='--', label='exploitability (max 3.9)')
a.set_xlabel('CVSS v3.1 sub-score'); a.set_ylabel('vulnerabilities'); a.legend(frameon=False, fontsize=6.6, loc='upper left')
a.set_title('(c)', loc='left', fontsize=8.5)

a = ax[1, 1]
ep = X[:, 5]
a.hist(np.log10(ep), bins=np.arange(-5, .01, .2), color='0.35', edgecolor='k', lw=.4)
a.axvline(np.log10(np.median(ep)), color='k', lw=1, ls='--')
a.text(np.log10(np.median(ep)) + .25, a.get_ylim()[1] * .9, 'median %.4f' % np.median(ep), fontsize=6.8)
a.set_xticks(range(-5, 1)); a.set_xticklabels(['$10^{%d}$' % t if t else '1' for t in range(-5, 1)])
a.set_xlabel('EPSS on the last day of the month (log scale)'); a.set_ylabel('vulnerabilities')
a.set_title('(d)', loc='left', fontsize=8.5)
for r in ax.flat:
    r.spines[['top', 'right']].set_visible(False)
fig.tight_layout(); fig.savefig(os.path.join(FIG, 'fig_dataset.pdf'))
print('share EPSS<0.01: %.1f%%  >0.1: %.1f%%' % (100 * np.mean(ep < .01), 100 * np.mean(ep > .1)))
print('impact>=5: %.1f%%' % (100 * np.mean(X[:, 4] >= 5)), 'expl levels', [round(100*np.mean(e==v),1) for v in (0,.5,1)],
      'autom yes %.1f tech total %.1f' % (100*X[:,1].mean(), 100*X[:,2].mean()), 'median epss', np.median(ep), 'impact median', np.median(X[:,4]), 'expl median', np.median(X[:,3]))
