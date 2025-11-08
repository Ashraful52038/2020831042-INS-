import random, math, string
from collections import Counter

CIPHER1 = ("af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eao-"
"-wvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg "
"du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm "
"epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvc-"
"-pfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnir--ceiki tdvng pc niprc kiopaf dfi "
"mddg oafg cepc tdvng qdfcafvi cei kiripkqe")

CIPHER2 = ("aceah toz puvg vcdl omj puvg yudqecov, omj loj auum klu thmjuv hs klu zlcvu shv "
"zcbkg guovz, upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm. klu "
"vcdluz lu loj avhqnlk aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumj, omj ck toz "
"yhyqeoveg auecupuj, tlokupuv klu hej sher wcnlk zog, klok klu lcee ok aon umj toz sqee hs "
"kqmmuez zkqssuj tckl kvuozqvu. omj cs klok toz mhk umhqnl shv sowu, kluvu toz oezh lcz "
"yvhehmnuj pcnhqv kh wovpue ok. kcwu thvu hm, aqk ck zuuwuj kh lopu eckkeu ussudk hm "
"wv. aonncmz. ok mcmukg lu toz wqdl klu zowu oz ok scskg. ok mcmukg-mcmu klug aunom kh "
"doee lcw tuee-yvuzuvpuj; aqk qmdlomnuj thqej lopu auum muovuv klu wovr. kluvu tuvu zhwu "
"klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn; ck zuuwuj qmsocv klok "
"omghmu zlhqej yhzzuzz (oyyovumkeg) yuvyukqoe ghqkl oz tuee oz (vuyqkujeg) "
"cmubloqzkcaeu tuoekl. ck tcee lopu kh au yocj shv, klug zocj. ck czm'k mokqvoe, omj kvhqaeu "
"tcee dhwu hs ck! aqk zh sov kvhqaeu loj mhk dhwu; omj oz wv. aonncmz toz numuvhqz tckl "
"lcz whmug, whzk yuhyeu tuvu tceecmn kh shvncpu lcw lcz hjjckcuz omj lcz nhhj shvkqmu. lu "
"vuwocmuj hm pczckcmn kuvwz tckl lcz vueokcpuz (ubduyk, hs dhqvzu, klu zodrpceeu￾aonncmzuz), omj lu loj womg juphkuj ojwcvuvz owhmn klu lhaackz hs yhhv omj "
"qmcwyhvkomk sowcecuz. aqk lu loj mh dehzu svcumjz, qmkce zhwu hs lcz ghqmnuv dhqzcmz "
"aunom kh nvht qy. klu uejuzk hs kluzu, omj aceah'z sophqvcku, toz ghqmn svhjh aonncmz. "
"tlum aceah toz mcmukg-mcmu lu ojhykuj svhjh oz lcz lucv, omj avhqnlk lcw kh ecpu ok aon "
"umj; omj klu lhyuz hs klu zodrpceeu- aonncmzuz tuvu scmoeeg jozluj. aceah omj svhjh "
"loyyumuj kh lopu klu zowu acvkljog, zuykuwauv 22mj. ghq loj aukkuv dhwu omj ecpu luvu, "
"svhjh wg eoj, zocj aceah hmu jog; omj klum tu dom dueuavoku hqv acvkljog-yovkcuz "
"dhwshvkoaeg khnukluv. ok klok kcwu svhjh toz zkcee cm lcz ktuumz, oz klu lhaackz doeeuj klu "
"cvvuzyhmzcaeu ktumkcuz auktuum dlcejlhhj omj dhwcmn hs onu ok klcvkg-klvuu")

# --- English statistics ---
EN_FREQ = {  # from lab table
    'a':8.05,'b':1.67,'c':2.23,'d':5.10,'e':12.22,'f':2.14,'g':2.30,'h':6.62,
    'i':6.28,'j':0.19,'k':0.95,'l':4.08,'m':2.33,'n':6.95,'o':7.63,'p':1.66,
    'q':0.06,'r':5.29,'s':6.02,'t':9.67,'u':2.92,'v':0.82,'w':2.60,'x':0.11,
    'y':2.04,'z':0.06
}
ETAOIN = "etaoinshrdlucmfwypvbgkjqxz"
COMMON_NGRAMS = [
    # bigrams
    "th","he","in","er","an","re","on","at","en","nd","ti","es","or","te","of","ed","is","it","al","ar",
    # trigrams
    "the","and","ing","her","hat","his","tha","ere","for","ent","ion","ter","est","ers","ati","ati","all"
]
COMMON_WORDS = set("""
the of and to in is you that it he was for on are as with his they I at be this
have from or one had by word but not what all were we when your can said there use
an each which she do how their if will up other about out many then them these so
""".split())

def only_letters(s): return [c for c in s.lower() if c in string.ascii_lowercase]

def monogram_chisq(text):
    letters = only_letters(text)
    n = len(letters) or 1
    cnt = Counter(letters)
    score = 0.0
    for c in string.ascii_lowercase:
        obs = 100.0*cnt.get(c,0)/n
        exp = EN_FREQ[c]
        score += (obs-exp)**2/exp
    return score

def ngram_bonus(text):
    t = ''.join(only_letters(text))
    bonus = 0
    for ng in COMMON_NGRAMS:
        bonus += 2 * t.count(ng) * len(ng)  # longer n-gram -> বেশি বোনাস
    return bonus

def word_bonus(text):
    words = [''.join(ch for ch in w.lower() if ch in string.ascii_lowercase)
             for w in text.split()]
    hits = sum(1 for w in words if w in COMMON_WORDS)
    return 3 * hits

def score(text):
    # কম স্কোর ভালো (chi-square), তাই বোনাসগুলো minus করে দিচ্ছি
    return monogram_chisq(text) - ngram_bonus(text) - word_bonus(text)

def make_initial_key(ct):
    # frequency mapping: cipher freq rank -> ETAOIN rank
    letters = only_letters(ct)
    freq = Counter(letters)
    cipher_order = ''.join([p for p,_ in freq.most_common()])
    # বাকিগুলো অ্যাপেন্ড
    for c in string.ascii_lowercase:
        if c not in cipher_order:
            cipher_order += c
    mapping = {}
    for i,c in enumerate(cipher_order):
        mapping[c] = ETAOIN[i] if i < 26 else c
    # mapping -> key string (plain_for_cipher[c])
    key = ['?']*26
    for i,c in enumerate(string.ascii_lowercase):
        key[i] = mapping[c]
    return ''.join(key)  # key[i]=plain letter for cipher chr(97+i)

def apply_key(ct, key):
    # key: 26-length string; for cipher 'a'..'z' gives corresponding plain
    table = {c:key[i] for i,c in enumerate(string.ascii_lowercase)}
    out=[]
    for ch in ct:
        lc = ch.lower()
        if lc in table:
            p = table[lc]
            out.append(p.upper() if ch.isupper() else p)
        else:
            out.append(ch)
    return ''.join(out)

def random_swap(key):
    a,b = random.sample(range(26),2)
    lst = list(key)
    lst[a],lst[b] = lst[b],lst[a]
    return ''.join(lst)

def improve(ct, key, iters=4000):
    best = key
    best_plain = apply_key(ct, best)
    best_score = score(best_plain)
    cur, cur_score = best, best_score

    for i in range(iters):
        cand = random_swap(cur)
        cand_plain = apply_key(ct, cand)
        cand_score = score(cand_plain)
        if cand_score < cur_score or random.random() < 0.001:  # ছোট্ট এক্সপ্লোরেশন
            cur, cur_score = cand, cand_score
            if cur_score < best_score:
                best, best_plain, best_score = cur, cand_plain, cand_score
    return best, best_plain, best_score

def break_substitution(ct, restarts=20, iters=4000):
    best_key, best_plain, best_score = None, None, 1e18
    init = make_initial_key(ct)
    for r in range(restarts):
        # প্রতিবার সামান্য শাফল দিয়ে শুরু
        key0 = init
        for _ in range(200): key0 = random_swap(key0)
        k, p, s = improve(ct, key0, iters)
        if s < best_score:
            best_key, best_plain, best_score = k, p, s
    return best_key, best_plain

if __name__ == "__main__":
    for i, CT in enumerate([CIPHER1, CIPHER2], start=1):
        key, plain = break_substitution(CT, restarts=30, iters=6000)
        print("="*60)
        print(f"Cipher-{i} best key (cipher a..z -> plain):\n{key}")
        print("\nDecryption:\n")
        print(plain)
        print()
