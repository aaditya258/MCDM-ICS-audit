#!/usr/bin/env python3
"""August 2026 in detail (Section 5.1, Tables 3 to 5) and the ordinal coding check (Section 5.3).

    python scripts/worked_month.py
"""
import os, glob, json
import numpy as np
from _common import MATRICES, PUBLISHED, OUT, FIG
from normaudit import audit, load_matrix_csv
from normaudit.methods import *
PAIR_A,PAIR_B='CVE-2026-19670','CVE-2026-76060'   # worked pair of Section 5.1
p=load_matrix_csv(os.path.join(MATRICES,'ics_2026_08.csv')); X=p.X; o=p.o; w=p.w; n=len(X); names=p.alternatives
a=audit(X,o,w); wc=w/a.kappa; wc/=wc.sum()
s=saw_minmax(X,o,w); v=wsm_vector(X,o,w); t=topsis(X,o,w); tm=topsis_minmax(X,o,w); tc=topsis(X,o,wc)
fl=set(map(tuple,a.flagged_pairs)); inv=set(inverted_pairs(s,t)); rs,rt,rc,rv=ranking(s),ranking(t),ranking(tc),ranking(v)
print('n',n,'pairs',n*(n-1)//2,'distinct',len(set(map(tuple,X))))
for j,c in enumerate(p.criteria):
    col=X[:,j]; print('%-22s min %.5f med %.5f max %.5f norm %.3f kappa %.3f w~ %.3f shift %+.1f w* %.3f nonzero %d'%(c,col.min(),np.median(col),col.max(),np.linalg.norm(col),a.kappa[j],a.w_eff[j],a.shift_pp[j],wc[j],(col>0).sum()))
print('nu %.2f dw %.3f flag %d normonly %d topsis %d tmm %d comp %d both %d prec %.3f rec %.3f'%(a.nu,a.delta_w,len(fl),len(inverted_pairs(s,v)),len(inv),len(inverted_pairs(s,tm)),len(inverted_pairs(s,tc)),len(fl&inv),len(fl&inv)/len(fl),len(fl&inv)/len(inv)))
print('tau v %.3f t %.3f c %.3f eq %.1e'%(kendall_tau_b(s,v),kendall_tau_b(s,t),kendall_tau_b(s,tc),np.max(np.abs(tc-tm))))
for nm_,r in [('v',rv),('t',rt),('c',rc)]: print('disp',nm_,round(np.abs(rs-r).mean(),1),int(np.abs(rs-r).max()))
for k in (5,10,20): print('top',k,[len(set(np.argsort(-s)[:k])&set(np.argsort(-x)[:k])) for x in (v,t,tc)])
print('expl counts',{val:int((X[:,0]==val).sum()) for val in sorted(set(X[:,0]))},'autom yes',int(X[:,1].sum()),'TI total',int(X[:,2].sum()))
for c in [PAIR_A,PAIR_B]:
    i=names.index(c); print(c,X[i],'add %g topsis %g comp %g'%(rs[i],rt[i],rc[i]))
i=names.index(PAIR_A); j=names.index(PAIR_B); R=X.max(0)-X.min(0); aj=w*(X[i]-X[j])/R
print('a',np.round(aj,4),'s1 %.4f'%aj.sum(),'ka',np.round(a.kappa*aj,4),'s2 %.4f'%(a.kappa*aj).sum(),'flag',tuple(sorted((i,j))) in fl)
poc=[k for k in range(n) if X[k,0]==0.5]; print('poc:',[(names[k],X[k,2],X[k,4],rs[k],rt[k],rc[k]) for k in poc])
print('top5 add:',[(names[k],rt[k]) for k in np.argsort(rs)[:5]])
# encoding B
XA=X.copy(); XA[:,0]=np.where(X[:,0]==0,1/3,np.where(X[:,0]==.5,2/3,1)); XA[:,1]=np.where(X[:,1]==0,.5,1); XA[:,2]=np.where(X[:,2]==0,.5,1)
aA=audit(XA,o,w); sA=saw_minmax(XA,o,w); vA=wsm_vector(XA,o,w); tA=topsis(XA,o,w); wA=w/aA.kappa; wA/=wA.sum(); tcA=topsis(XA,o,wA)
print('ENC alt kappa',np.round(aA.kappa,3),'dw %.3f'%aA.delta_w,'same additive',np.array_equal(ranking(s),ranking(sA)),'vec differ pairs',len(inverted_pairs(v,vA)),'topsis differ pairs',len(inverted_pairs(t,tA)),'alt topsis inv',len(inverted_pairs(sA,tA)),'alt comp',len(inverted_pairs(sA,tcA)))

