import csv, sys
import inspect
from generaldata import blackword, unrelated_cves, related_cves, yearstart
from config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
import threading, pymysql, warnings
thread_data = threading.local()

def db():
    global thread_data
    conn = pymysql.connect(user=MYSQL_USER,passwd=MYSQL_PASSWORD,host=MYSQL_HOST,port=MYSQL_PORT,db=MYSQL_DB ,charset='utf8',init_command="set NAMES utf8mb4", use_unicode=True)
    thread_data.__dict__["conn"] = conn
    return conn

def runsql(sql, *args, onerror='raise', returnid=False, allow_retry=True):
    global thread_data
    conn = thread_data.__dict__.get("conn")
    if not conn:
        conn = db()
    if not conn.open:
        conn = db()
    cur = conn.cursor()
    try:
        conn.ping()
    except:
        print("conn.ping() failed, reconnect")
        conn = db()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cur.execute(sql, args)
    except pymysql.err.OperationalError as e:
        conn.commit()
        cur.close()
        if allow_retry and ("Lost connection to MySQL" in str(e) or "MySQL server has gone away" in str(e)):
            conn.close()
            conn = db()
            return runsql(sql, *args, onerror=onerror, returnid=returnid, allow_retry=False)
        else:
            raise
    except:
        conn.commit()
        cur.close()
        if onerror=="ignore":
            return False
        else:
            raise
    if returnid:
        cur.execute("SELECT LAST_INSERT_ID();")
        result = list(cur)[0][0]
    else:
        result = list(cur)
    conn.commit()
    cur.close()
    return result


def dprint(*args):
    return
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

CVSSDATA={}
for cveid,cwes,cvssv3,cvssv2,vectorv3,vectorv2 in csv.reader(open("cvss.csv")):
    CVSSDATA[cveid] = [cwes,cvssv3,cvssv2,vectorv3,vectorv2]

class TABLE():
    def __init__(self):
        if not getattr(self.__class__, "attributes", None):
            self.__class__.attributes = [a[0] for a in inspect.getmembers(self.__class__, lambda a:not(inspect.isroutine(a))) if not(a[0].startswith('__') and a[0].endswith('__'))]
    
    def save(self):
        sql = "replace into "+self.__class__.__name__.lower()+"(`" + "`,`".join(self.attributes)+"`) values ("+ ("%s,"*len(self.attributes))[:-1] +")"
        values = [getattr(self, key) for key in self.attributes]
        #print(sql, values)
        return runsql(sql, *values)

class CVE_general(TABLE):
    id = "" # CVE id
    related = 1 # is related to our unibench programs
    project = "" # the library name, actually search keyword, 
    binary = "" # the binary name in description
    version_description = "" # largest version mentioned in description, may be largest vulnerable version or smallest fixed version
    vuln_type_description = "" # vulnerability type extracted and transformed from CVE description
    vuln_func_description = "" # function name (class name may be present) extracted from description, e.g. Exiv2::Image::printTiffStructure
    vuln_purefunc_description = "" # pure function name, without class name prefix, e.g. printTiffStructure
    vuln_file_description = "" # vulnerable file mentioned in description
    description = "" # raw description text
    useful_link = "" # possible useful links for extracting vulnerability report, concatenated by ###
    cwe = "" # CWE information related to this CVE, downloaded from NVD database, concatenated by /
    cvssv3 = 0.0 # CVSS v3, -1 is unavailable
    cvssv2 = 0.0 # CVSS v2
    cpe3 = "" # CPE v3
    cpe2 = "" # CPE v2

def wordin(list, item):
    return " "+item+" " in " "+(" ".join(list))+" "

def parse_vuln_type(text):
    textwords = []
    text = text.replace("over-read", "overflow")
    for t in text.lower().replace("-", " ").replace("("," ").split():
        t = t.strip(",.;\"'()")
        if t.endswith("'s"):
            t = t[:-2]
        t = {"writes":"write", "reads":"read"}.get(t,t)
        textwords.append(t)
    translate_dict = {
        "invalid free":"free_error", 
        "heap based buffer overflow":"heap-buffer-overflow", 
        "stack based buffer overflow":"stack-buffer-overflow",
        "floating point exception":"FloatingPointException",
        "fpe": "FloatingPointException",
        "divide by zero": "FloatingPointException",
        "heap buffer overflow": "heap-buffer-overflow",
        "uncontrolled recursion": "stack-overflow",
        "stack consumption": "stack-overflow",
        "stack overflow": "stack-overflow",
        "excessive recursion": "stack-overflow",
        "excessive memory allocation": "excessive_memory_allocation",
        "buffer over read": "buffer-overflow",
        "buffer overflow": "buffer-overflow",
        "out of bounds read": "buffer-overflow",
        "out of bounds write": "buffer-overflow",
        "invalid read": "buffer-overflow",
        "read access violation": "SEGV",
        "invalid memory access": "SEGV",
        "segv": "SEGV",
        "sigsgev": "SEGV",
        "address access exception": "SEGV",
        "segmentation violation": "SEGV",
        "segmentation fault": "SEGV",
        "assertion failure": "assertion_failure",
        "memory leak": "memory_leak",
        
    }
    for t in list(translate_dict.keys())+[
        "infinite loop", "null pointer dereference", 
        "use-after-free"
    ]:
        if wordin(textwords, t):
            return translate_dict.get(t, t)
    return None

def fprint(fp, *args):
    return fp.write("\t".join([str(i) for i in args])+"\n")

proglist = "exiv2 gdk-pixbuf jasper jhead libtiff lame mp3gain swftools ffmpeg flvmeta Bento4 cflow ncurses jq mujs xpdf sqlite sqlite3 binutils tcpdump".split(" ")
handled_cveids = []
fp1 = open("1.txt", "w")
fp2 = open("2.txt", "w")
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
    cwes,cvssv3,cvssv2,vectorv3,vectorv2 = CVSSDATA[id]
    vuln_type = parse_vuln_type(desc)
    if vuln_type:
        fprint(fp1, id, vuln_type, desc)
    else:
        fprint(fp2, id, desc)
    #print(prog,id, desc, )
    x = CVE_general()
    x.id = id
    x.project = prog
    x.description = desc
    x.cwe = cwes
    x.cvssv3 = cvssv3
    x.cvssv2 = cvssv2
    x.cpe3 = vectorv3
    x.cpe2 = vectorv2
    #x.save()
    