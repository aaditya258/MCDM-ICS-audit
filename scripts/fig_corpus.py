#!/usr/bin/env python3
"""Figure 3. Run audit_corpus.py and run_published.py first."""
import os,json,numpy as np,matplotlib; matplotlib.use('Agg')
from _common import OUT,FIG
import matplotlib.pyplot as plt
res=json.load(open(os.path.join(OUT,'audit_results.json')))
ics=np.array([r['dw'] for r in res])
pub=json.load(open(os.path.join(OUT,'published_results.json')))
five=np.array([pub[k]['dw'] for k in sorted(pub)])
plt.rcParams.update({'font.size':8.5,'font.family':'serif'})
fig,ax=plt.subplots(1,2,figsize=(7.1,3.2))
# (a) distribution comparison - every matrix shown, median marked
rng=np.random.default_rng(7)
for i,(v,lab,mk,fc) in enumerate([(ics,'ICS monthly\n(33 matrices)','o','0.35'),
                                  (five,'five published\nproblems','^','white')]):
    x=i+rng.uniform(-.11,.11,len(v))
    ax[0].scatter(x,v,s=13,marker=mk,facecolor=fc,edgecolor='k',linewidth=.5,zorder=3)
    md=np.median(v)
    ax[0].plot([i-.26,i+.26],[md,md],color='k',lw=1.6,zorder=4)
    ax[0].text(i+.30,md,r'median %.3f'%md,va='center',fontsize=7)
ax[0].set_xticks([0,1]); ax[0].set_xticklabels(['ICS monthly\n(33 matrices)','five published\nproblems'])
ax[0].set_xlim(-.5,1.75); ax[0].set_ylim(0,.5)
ax[0].set_ylabel(r'weight shift $\delta_w$')
ax[0].set_title('(a)',loc='left',fontsize=8.5)
ax[0].grid(axis='y',color='0.88',lw=.5); ax[0].set_axisbelow(True)
# (b) paired dumbbell: classical TOPSIS -> compensated, one row per matrix
o=sorted(range(len(res)),key=lambda i:res[i]['tau_t'])
y=np.arange(len(o))
tt=np.array([res[i]['tau_t'] for i in o]); tc=np.array([res[i]['tau_c'] for i in o])
for k in range(len(o)):
    ax[1].plot([tt[k],tc[k]],[y[k],y[k]],color='0.55',lw=.8,zorder=2,solid_capstyle='butt')
ax[1].scatter(tt,y,s=13,marker='o',facecolor='0.35',edgecolor='k',linewidth=.4,zorder=3,label='classical TOPSIS')
ax[1].scatter(tc,y,s=15,marker='^',facecolor='white',edgecolor='k',linewidth=.5,zorder=3,label=r'under $\mathbf{w}^*$')
ax[1].set_yticks([0,len(o)-1]); ax[1].set_yticklabels(['worst','best'],fontsize=7.5)
ax[1].set_ylim(-1.2,len(o))
ax[1].set_xlim(.42,1.02)
ax[1].set_xlabel(r'Kendall $\tau_b$ against the min-max additive model')
ax[1].set_ylabel('the 33 monthly matrices,\nordered by TOPSIS agreement',fontsize=7.5)
ax[1].legend(frameon=False,fontsize=6.8,loc='lower left',handletextpad=.3)
ax[1].set_title('(b)',loc='left',fontsize=8.5)
ax[1].grid(axis='x',color='0.88',lw=.5); ax[1].set_axisbelow(True)
fig.tight_layout(); fig.savefig(os.path.join(FIG,'fig_corpus.pdf')); print('ok')
