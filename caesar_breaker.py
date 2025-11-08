from collections import Counter
import string
CIPHER = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"

EN_FREQ = {  # From the lab's table (Tom Sawyer)
    'a':8.05,'b':1.67,'c':2.23,'d':5.10,'e':12.22,'f':2.14,'g':2.30,'h':6.62,
    'i':6.28,'j':0.19,'k':0.95,'l':4.08,'m':2.33,'n':6.95,'o':7.63,'p':1.66,
    'q':0.06,'r':5.29,'s':6.02,'t':9.67,'u':2.92,'v':0.82,'w':2.60,'x':0.11,
    'y':2.04,'z':0.06
}

def shift_text(s, k):
    out=[]
    for ch in s:
        if 'a'<=ch<='z':
            out.append(chr((ord(ch)-97-k)%26+97))
        elif 'A'<=ch<='Z':
            out.append(chr((ord(ch)-65-k)%26+65))
        else:
            out.append(ch)
    return ''.join(out)

def chisq_score(text):
    only = [c for c in text.lower() if c in string.ascii_lowercase]
    n = len(only) or 1
    cnt = Counter(only)
    score = 0.0
    for c in string.ascii_lowercase:
        obs = 100.0*cnt.get(c,0)/n
        exp = EN_FREQ[c]
        score += (obs-exp)**2/exp
    return score

best_k, best_plain, best_score = None, None, 1e9
for k in range(26):
    p = shift_text(CIPHER, k)
    s = chisq_score(p)
    if s < best_score:
        best_k, best_plain, best_score = k, p, s

print(f"Best shift = {best_k}")
print(best_plain)
