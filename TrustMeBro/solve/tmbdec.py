import numpy as np, math
def G(x): 
    f=np.floor(x); return f*0.5+np.maximum(0.0,(x-f)-0.5)
def p1_table(W,h):
    w=np.arange(1<<W,dtype=np.float64); a=h*w/(1<<W); L=h/(1<<W)
    return (G(a+L)-G(a))/L
class Dec:
    def __init__(s,W,eps,pool):
        s.W=W; s.eps=eps; s.pool=pool
        s.P1={h:p1_table(W,h) for h in pool}
    def loglik(s,obs_t):
        # obs_t: list of (h,bit) at scale t -> log P(obs | window) over 2^W windows
        m=np.zeros(1<<s.W); e=s.eps
        for h,b in obs_t:
            p=s.P1[h]*(1-e)+(1-s.P1[h])*e
            m+=np.log(p if b else 1-p)
        return m
    def posterior(s,obs,nbits):
        """obs: dict t -> list[(h,bit)]. bits indexed 0..nbits-1 ; scale t covers bits t..t+W-1 (window oldest..newest)."""
        W=s.W; S=1<<(W-1)
        M=[None]*nbits
        for i in range(nbits):
            t=i-(W-1)
            M[i]=s.loglik(obs[t]) if (t>=0 and t in obs and obs[t]) else np.zeros(1<<W)
        wins=np.arange(1<<W)
        def lse2(a,b):
            mx=np.maximum(a,b); return mx+np.log(np.exp(a-mx)+np.exp(b-mx))
        alpha=np.zeros((nbits+1,S),dtype=np.float32); alpha[0]=-np.log(S)
        for i in range(nbits):
            c=alpha[i][wins>>1]+M[i]
            a=lse2(c[:S],c[S:]); a-=a.max(); alpha[i+1]=a
        beta=np.zeros((nbits+1,S),dtype=np.float32)
        for i in range(nbits-1,-1,-1):
            c=M[i]+beta[i+1][wins&(S-1)]            # per window, to be summed over oldest bit? sum over windows with same prev state
            # prev state = w>>1 ; two windows per prev state: w=2*sp+b
            c2=c.reshape(S,2)
            b_=lse2(c2[:,0],c2[:,1]); b_-=b_.max(); beta[i]=b_
        llr=np.zeros(nbits)
        for i in range(nbits):
            c=alpha[i][wins>>1]+M[i]+beta[i+1][wins&(S-1)]
            odd=c[1::2]; even=c[0::2]
            mo=odd.max(); me=even.max()
            llr[i]=(mo+np.log(np.exp(odd-mo).sum()))-(me+np.log(np.exp(even-me).sum()))
        return llr
