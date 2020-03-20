import csv, sys
import inspect
from generaldata import blackword, unrelated_cves, related_cves, yearstart, lessuseful_domains, bins
from config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
import threading, pymysql, warnings
from poccrawler import downloadpocfile
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
        t = {"writes":"write", "reads":"read", "overflows":"overflow", "leaks":"leak",
             "overflowing":"overflow", "uninitialised":"uninitialized", "int32":"integer"}.get(t,t)
        textwords.append(t)
    translate_dict = {
        "invalid free":"free_error", 
        "heap based buffer overflow":"heap-buffer-overflow", 
        "stack based buffer overflow":"stack-buffer-overflow",
        "stack based buffer under read":"stack-buffer-underflow",
        "floating point exception":"FloatingPointException",
        "fpe": "FloatingPointException",
        "divide by zero": "FloatingPointException",
        "division by zero": "FloatingPointException",
        "heap buffer overflow": "heap-buffer-overflow",
        "heap overflow": "heap-buffer-overflow",
        "out-of-bounds heap access": "heap-buffer-overflow",
        "uncontrolled recursion": "stack-overflow",
        "stack consumption": "stack-overflow",
        "stack overflow": "stack-overflow",
        "excessive recursion": "stack-overflow",
        "infinite recursion": "stack-overflow",
        "unlimited recursion": "stack-overflow",
        "stack exhaustion": "stack-overflow",
        "excessive memory allocation": "excessive_memory_allocation",
        "memory consumption": "excessive_memory_allocation",
        "uncontrolled memory allocation": "excessive_memory_allocation",
        "buffer over read": "buffer-overflow",
        "buffer overflow": "buffer-overflow",
        "out of bounds": "buffer-overflow",
        "out of array": "buffer-overflow",
        "invalid read": "buffer-overflow",
        "off by one": "buffer-overflow",
        "use after free": "use-after-free",
        "access violation": "SEGV",
        "write memory access violation": "SEGV",
        "read memory access violation": "SEGV",
        "invalid memory write": "SEGV",
        "invalid memory access": "SEGV",
        "illegal address access": "SEGV",
        "invalid memory read": "SEGV",
        "invalid pointer access": "SEGV",
        "invalid address dereference": "SEGV",
        "invalid pointer dereference": "SEGV",
        "segv": "SEGV",
        "sigsegv": "SEGV",
        "address access exception": "SEGV",
        "segmentation violation": "SEGV",
        "segmentation fault": "SEGV",
        "assertion failure": "assertion_failure",
        "assertion abort": "assertion_failure",
        "reachable assertion": "assertion_failure",
        "reachable abort": "assertion_failure", # SIGABRT instead?
        "assert fault": "assertion_failure",
        "assertion violation": "assertion_failure",
        "memory leak": "memory_leak", #unrelated
        "infinite loop": "infinite_loop",
        "application hang": "infinite_loop",
        "null pointer dereference": "null_pointer_dereference",
        "null dereference": "null_pointer_dereference",
        "null pointer": "null_pointer_dereference",
        "double free": "double-free",
        "left shift of a negative value": "left_shift_negative", #need ubsan
        "sigabrt": "SIGABRT",
        "information leak":"information_leak", #unrelated
        "integer overflow": "integer-overflow",
        "integer underflow": "integer-underflow",
        "corruption": "memory_corruption",
        "code execution": "code_execution", #unrelated
        "outside the range of representable values": "type_overflow", #need ubsan
        "uninitialized": "uninitialized_memory_access" #maybe need msan
    }
    for t in translate_dict.keys():
        if wordin(textwords, t):
            return translate_dict.get(t, t)
    #fprint(fp2, textwords)
    return None

def parse_vuln_function(text):
    data = parse_vuln_function_yw(text)
    if not data:
        return data
    if data[-1] == ")":
        data.pop()
    return "###".join(data)

def getwords(text, trimlist=",.;"):
    words=[]
    for t in text.lower().split():
        t = t.strip(trimlist)
        words.append(t)
    return words

# text is the description of a CVE
def parse_vuln_function_yw(text):
    textwords=getwords(text)
    # print(textwords)

    # if "bfd_elf_final_link" in text:
    #     print (text)
    # print(type(text))
    # text = text.replace("over-read", "overflow")
    # for t in text.lower().replace("-", " ").replace("("," ").split():
    #     t = t.strip(",.;\"'()")
    #     if t.endswith("'s"):
    #         t = t[:-2]
    #     t = {"writes":"write", "reads":"read"}.get(t,t)
    #     textwords.append(t)
    # print(textwords)
    non_func=["","the", "at", "in", "a", "an"]
    ext = [".c", ".cpp", ".h", ".hpp"]
    whitelist=["getData"]
    for i in range(0, len(textwords)):
        if textwords[i]=="function":
            vuln_func=textwords[i-1]
            if vuln_func in non_func:
                continue
            #print("vulnable function: %s"%vuln_func)
            vuln_func = vuln_func.split('(')
            return vuln_func

        if textwords[i] == "function":
            vuln_func = textwords[i+1]
            if vuln_func in non_func:
                continue
            if "_" in vuln_func:
                #print("--------------------vulnable function: %s"%vuln_func)
                vuln_func = vuln_func.split('(')
                return vuln_func


        if "::" in textwords[i]:
            vuln_func=textwords[i]
            if vuln_func in non_func:
                continue
            #print("vulnable function: %s"%vuln_func)
            vuln_func = vuln_func.split('(')
            return vuln_func

        # if "()" in textwords[i] or "::" in textwords[i]:
        if "()" in textwords[i]:
            vuln_func = textwords[i]
            if vuln_func in non_func:
                continue
           
            if ".c:" in vuln_func or ".cpp:" in vuln_func:
                vuln_func = vuln_func.split(":")[1]
                # print("after split %s"%vuln_func)
                
            #print("vulnable function: %s"%vuln_func)
            vuln_func = vuln_func.split('(')
            return vuln_func

        if textwords[i] == "in":
            if textwords[i+1].endswith(tuple(ext)):
                continue
            vuln_func = textwords[i+1]
            if textwords[i+1] == "the":
                vuln_func = textwords[i+2]

            if vuln_func in non_func:
                continue

            elif "_" in vuln_func:
                if ".c:" in vuln_func or ".cpp:" in vuln_func:
                    vuln_func = vuln_func.split(":")[1]
                #print("vulnable function: %s"%vuln_func)
                vuln_func = vuln_func.split('(')
                return vuln_func

    return None

def fprint(fp, *args):
    return fp.write("\t".join([str(i) for i in args])+"\n")

def logtofile(data, id, desc):
    global fp1, fp2
    if data:
        fprint(fp1, id, data, desc)
    else:
        fprint(fp2, id, desc)

def parse_vuln_file(text):
    ext = [".c", ".cpp", ".h", ".hpp", ".cc"]
    words = getwords(text.replace(":", " "), ",.;()\"")
    for w in words:
        for e in ext:
            if w.endswith(e):
                return w
    return None

def parse_binary(text):
    for w in getwords(text):
        if w in bins:
            return w
    return None

proglist = "exiv2 gdk-pixbuf jasper jhead libtiff lame mp3gain swftools ffmpeg flvmeta Bento4 cflow ncurses jq mujs xpdf sqlite sqlite3 binutils tcpdump".split(" ")
handled_cveids = []
fp1 = open("1.txt", "w")
fp2 = open("2.txt", "w")
start=False #TODO: remove this
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
    vuln_func = parse_vuln_function(desc)
    vuln_purefunc = vuln_func.split("###")[0].split(":")[-1] if vuln_func else None
    
    links = []
    
    for link in ref.split("|"):
        link = link.strip()
        if "MISC:" in link or "CONFIRM:" in link:
            url = link.replace("MISC:","").replace("CONFIRM:","")
            domain = link.split("://")[1].split("/",1)[0]
            if domain in lessuseful_domains:
                continue
            links.append(url)
            #print(link)
    def extract_version(text):
        for t in text.lower().replace("("," ").split():
            t = t.strip(",.;\"'()")
            if "." in t:
                if t.startswith("v"):
                    t = t[1:]
                if t.split(".")[0].isdigit():
                    return t
            if "-" in t:
                if t.split("-")[0].isdigit():
                    return t
            if len(t)>30 and all(map(lambda i:i.isdigit() or i in "abcdef", t)):
                return t
        return None
    #print(prog,id, desc, )
    version = extract_version(desc)
    #logtofile(version, id, desc)
    
    vuln_file_description = parse_vuln_file(desc)
    #logtofile(vuln_file_description, id, desc)
    
    binary = parse_binary(desc)
    logtofile(binary, id, desc)
    
    x = CVE_general()
    x.id = id
    x.project = prog
    x.description = desc
    x.cwe = cwes
    x.cvssv3 = cvssv3
    x.cvssv2 = cvssv2
    x.cpe3 = vectorv3
    x.cpe2 = vectorv2
    x.vuln_type_description = vuln_type
    x.vuln_func_description = vuln_func
    x.vuln_purefunc_description = vuln_purefunc
    x.version_description = version
    x.vuln_file_description = vuln_file_description
    x.binary = binary
    x.useful_link = "###".join(links)
    #if 1:
    if "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=16443" in links:
        start=True
    if start:
        downloadpocfile(id, links)
    #x.save()
