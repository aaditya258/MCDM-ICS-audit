#!/usr/bin/env python3
"""Figure 2 (August 2026)."""
import os,numpy as np,matplotlib; matplotlib.use('Agg')
from _common import MATRICES,FIG
import matplotlib.pyplot as plt
from normaudit import audit, load_matrix_csv
from normaudit.methods import *
p=load_matrix_csv(os.path.join(MATRICES,'ics_2026_08.csv')); X,o,w=p.X,p.o,p.w
a=audit(X,o,w); wc=w/a.kappa; wc/=wc.sum()
s=saw_minmax(X,o,w); t=topsis(X,o,w); tc=topsis(X,o,wc); rs,rt,rc=ranking(s),ranking(t),ranking(tc)
plt.rcParams.update({'font.size':8.5,'font.family':'serif'})
fig,ax=plt.subplots(1,2,figsize=(7.1,2.8))
lbl=['SSVC\nExploit.','SSVC\nAutom.','SSVC\nTech.Imp.','CVSS\nexploit.','CVSS\nimpact','EPSS']
x=np.arange(6); bw=0.27
ax[0].bar(x-bw,w,bw,color='0.25',edgecolor='k',lw=.6,label='stated $w_j$ (equal)')
ax[0].bar(x,a.w_eff,bw,color='0.75',edgecolor='k',lw=.6,label=r'effective $\tilde w_j$')
ax[0].bar(x+bw,wc,bw,facecolor='white',edgecolor='k',lw=.6,hatch='////',label='compensated $w^*_j$')
for i,k in enumerate(a.kappa): ax[0].text(i,max(w[i],a.w_eff[i],wc[i])+0.012,r'$\kappa$=%.2f'%k,ha='center',fontsize=6.2)
ax[0].set_xticks(x); ax[0].set_xticklabels(lbl,fontsize=6.8); ax[0].set_ylabel('weight'); ax[0].set_ylim(0,0.50)
ax[0].legend(frameon=False,fontsize=6.6,loc='upper left'); ax[0].set_title('(a)',loc='left',fontsize=8.5)
ax[0].grid(axis='y',color='0.88',lw=.5); ax[0].set_axisbelow(True)
ax[1].axhline(0,color='k',lw=.6,ls=':')
ax[1].scatter(rs,rt-rs,s=14,facecolor='0.35',edgecolor='none',marker='o',label='classical TOPSIS')
ax[1].scatter(rs,rc-rs,s=16,facecolor='none',edgecolor='k',lw=.6,marker='^',label=r'TOPSIS under $\mathbf{w}^*$')
ax[1].set_xlabel('rank under the min-max additive model'); ax[1].set_ylabel('rank displacement')
ax[1].legend(frameon=False,fontsize=6.8,loc='lower right'); ax[1].set_title('(b)',loc='left',fontsize=8.5)
ax[1].grid(color='0.88',lw=.5); ax[1].set_axisbelow(True)
fig.tight_layout(); fig.savefig(os.path.join(FIG,'fig_ics.pdf')); print('ok')
