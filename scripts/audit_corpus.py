#!/usr/bin/env python3
"""Audit and compensate all 33 monthly ICS matrices (Section 5.2, Table 6).

    python scripts/audit_corpus.py
"""
import os, glob, json
import numpy as np
from _common import MATRICES, PUBLISHED, OUT, FIG
from normaudit import audit, load_matrix_csv
from normaudit.methods import *
res=[]
for f in sorted(glob.glob(os.path.join(MATRICES,'ics_*.csv'))):
    p=load_matrix_csv(f); mo=os.path.basename(f)[4:11].replace('_','-')
    n,m=p.X.shape; o=p.o; w=p.w
    a=audit(p.X,o,w)
    kappa=a.kappa; keep=[j for j in range(m) if kappa[j]>0]
    ws=np.array(w,float).copy()
    wc=np.where(kappa>0,w/np.where(kappa>0,kappa,1),0.0); wc=wc/wc.sum()
    s=saw_minmax(p.X,o,w); v=wsm_vector(p.X,o,w); t=topsis(p.X,o,w); tm=topsis_minmax(p.X,o,w); tc=topsis(p.X,o,wc)
    fl=set(map(tuple,a.flagged_pairs)); inv=set(inverted_pairs(s,t))
    rs,rt,rc,rv=ranking(s),ranking(t),ranking(tc),ranking(v)
    P=n*(n-1)//2
    d=dict(month=mo,n=n,P=P,nu=float(a.nu),dw=float(a.delta_w),
           kappa=[float(x) for x in a.kappa],weff=[float(x) for x in a.w_eff],wstar=[float(x) for x in wc],
           dropped=[p.criteria[j] for j in getattr(a,'dropped',[])],
           flag=len(fl),normonly=len(inverted_pairs(s,v)),topsis=len(inv),tmm=len(inverted_pairs(s,tm)),comp=len(inverted_pairs(s,tc)),
           prec=len(fl&inv)/max(len(fl),1),rec=len(fl&inv)/max(len(inv),1),
           tau_v=kendall_tau_b(s,v),tau_t=kendall_tau_b(s,t),tau_c=kendall_tau_b(s,tc),
           disp_t=float(np.abs(rs-rt).mean()),disp_tmax=int(np.abs(rs-rt).max()),
           disp_c=float(np.abs(rs-rc).mean()),disp_cmax=int(np.abs(rs-rc).max()),
           sametop_t=bool(same_top(s,t)),sametop_c=bool(same_top(s,tc)),
           comp_eq_tmm=float(np.max(np.abs(tc-tm))))
    for k in (5,10,20):
        kk=min(k,n); S=set(np.argsort(-s)[:kk])
        d['top%d_t'%k]=len(S&set(np.argsort(-t)[:kk])); d['top%d_c'%k]=len(S&set(np.argsort(-tc)[:kk])); d['top%d_k'%k]=kk
    res.append(d)
json.dump(res,open(os.path.join(OUT,'audit_results.json'),'w'),indent=1)
print('%-8s %4s %6s %6s %6s %7s %7s %7s %6s %6s %6s'%('month','n','nu','dw','flag%','TOPSIS','comp','tau_T','tau_c','t10','c10'))
for r in res:
    print('%-8s %4d %6.2f %6.3f %5.1f%% %7d %7d %6.3f %6.3f %5d %5d'%(r['month'],r['n'],r['nu'],r['dw'],100*r['flag']/r['P'],r['topsis'],r['comp'],r['tau_t'],r['tau_c'],r['top10_t'],r['top10_c']))
d=np.array([r['dw'] for r in res]); nu=np.array([r['nu'] for r in res])
print('\n=== %d monthly ICS matrices'%len(res))
print('n: min %d median %d max %d  (total %d CVE-months)'%(min(r['n'] for r in res),int(np.median([r['n'] for r in res])),max(r['n'] for r in res),sum(r['n'] for r in res)))
print('delta_w: median %.3f IQR %.3f-%.3f min %.3f max %.3f'%(np.median(d),*np.percentile(d,[25,75]),d.min(),d.max()))
print('nu: median %.2f range %.2f-%.2f'%(np.median(nu),nu.min(),nu.max()))
print('identity check (flagged == normalization-only inversions in every matrix): %s'%all(r['flag']==r['normonly'] for r in res))
print('compensated == TOPSIS-minmax, max abs diff over corpus: %.2e'%max(r['comp_eq_tmm'] for r in res))
print('matrices with >=1 flagged pair: %d/%d'%(sum(r['flag']>0 for r in res),len(res)))
print('TOPSIS changes the top-ranked CVE: %d/%d ; compensated: %d/%d'%(sum(not r['sametop_t'] for r in res),len(res),sum(not r['sametop_c'] for r in res),len(res)))
print('pooled pairs %d ; flagged %d ; TOPSIS inv %d -> comp %d (%.0f%% removed)'%(sum(r['P'] for r in res),sum(r['flag'] for r in res),sum(r['topsis'] for r in res),sum(r['comp'] for r in res),100*(1-sum(r['comp'] for r in res)/sum(r['topsis'] for r in res))))
print('mean tau_b: norm-only %.3f  TOPSIS %.3f  compensated %.3f'%(np.mean([r['tau_v'] for r in res]),np.mean([r['tau_t'] for r in res]),np.mean([r['tau_c'] for r in res])))
print('mean displacement: TOPSIS %.1f (max %d)  compensated %.1f (max %d)'%(np.mean([r['disp_t'] for r in res]),max(r['disp_tmax'] for r in res),np.mean([r['disp_c'] for r in res]),max(r['disp_cmax'] for r in res)))
for k in (5,10,20):
    print('top-%d retained: TOPSIS %.1f  compensated %.1f'%(k,np.mean([r['top%d_t'%k] for r in res]),np.mean([r['top%d_c'%k] for r in res])))
print('compensation reduces inversions in %d/%d matrices'%(sum(r['comp']<r['topsis'] for r in res),len(res)))
print('flag vs TOPSIS: mean precision %.3f  mean recall %.3f'%(np.mean([r['prec'] for r in res]),np.mean([r['rec'] for r in res])))
K=np.array([r['kappa'] for r in res]); W=np.array([r['weff'] for r in res])
nm=['SSVC Expl','SSVC Autom','SSVC TechImp','CVSS expl','CVSS imp','EPSS']
print('\n%-14s %14s %16s'%('criterion','median kappa','median w_eff (stated .167)'))
for j,c in enumerate(nm):
    kk=K[:,j][K[:,j]>0]
    print('%-14s %14.3f %16.3f'%(c,np.median(kk),np.nanmedian(W[:,j])))

import csv
cols=['month','n','P','nu','dw','flag','normonly','topsis','tmm','comp','prec','rec','tau_v','tau_t','tau_c','disp_t','disp_c','top5_t','top5_c','top10_t','top10_c','top20_t','top20_c','sametop_t','sametop_c']
with open(os.path.join(OUT,'results_by_month.csv'),'w',newline='') as fh:
    wr=csv.writer(fh); wr.writerow(cols)
    for r in res: wr.writerow([round(r[c],4) if isinstance(r[c],float) else r[c] for c in cols])
print('\nwrote outputs/audit_results.json and outputs/results_by_month.csv')
