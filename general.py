import csv, sys
from generaldata import blackword, unrelated_cves, related_cves, yearstart

def dprint(*args):
    sys.stderr.write("\t".join([str(i) for i in args])+"\n")

def wordpresent(words, text):
    textwords = []
    for word in words.split():
        for t in text.lower().replace("("," ").split():
            t = t.strip(",.;\"'()")
            if t.endswith("'s"):
                t = t[:-2]
            textwords.append(t)
        if word.lower() in textwords:
            continue
        else:
            return False
    return True

proglist = "exiv2 gdk-pixbuf jasper jhead libtiff lame mp3gain swftools ffmpeg flvmeta Bento4 cflow ncurses jq mujs xpdf sqlite sqlite3 binutils tcpdump".split(" ")
handled_cveids = []
for id, _, desc, ref, _, _, _ in csv.reader(open("unibench_cve.csv")):
    #print(id, description)
    if id in unrelated_cves:
        continue #filtered by blacklist
    year = int(id.split("-")[1])
    if year<yearstart:
        continue # filtered by year, we ignore too old CVEs
    if id in handled_cveids:
        continue # there are duplicated entries, ignore if we meet it twice
    filtered = False
    if id not in related_cves:
        for word in blackword:
            if wordpresent(word, desc):
                dprint("blackword", word, id, desc)
                filtered = True # filtered by black word list
    if filtered:
        continue
    progtmp = None
    for p in proglist:
        if wordpresent(p, desc):
            prog = p
            break
        elif p in desc.lower():
            progtmp = p
    else:
        if progtmp:
            dprint("no prog", id, p, desc)
        continue # filtered by program keyword not present in description
    prog = {"sqlite3":"sqlite"}.get(prog, prog)
    handled_cveids.append(id)
    print(prog,id, desc)