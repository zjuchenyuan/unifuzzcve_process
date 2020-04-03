import csv, sys, os
import inspect
from generaldata import blackword, unrelated_cves, related_cves, yearstart, lessuseful_domains, bins
from config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, POCFOLDER
import threading, pymysql, warnings, traceback
from poccrawler import downloadpocfile, pocfile_organize, clearpending
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
        values = []
        for key in self.attributes:
            v = getattr(self, key)
            if isinstance(v, list) or isinstance(v, tuple):
                v = "###".join(v)
            values.append(v)
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

def getwords(text, trimlist=",.;", tolower=True):
    words=[]
    if tolower:
        text = text.lower()
    for t in text.split():
        t = t.strip(trimlist)
        words.append(t)
    return words

# text is the description of a CVE
def parse_vuln_function_yw(text):
    textwords=getwords(text, tolower=False)
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
todo=[]
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
        if "MISC:" in link or "CONFIRM:" in link or "URL:" in link:
            url = link.replace("MISC:","").replace("CONFIRM:","").replace("URL:","")
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
    x.useful_link = "###".join([i for i in links if i])
    if prog!="exiv2": #TODO: delete this filter
        continue
    #if 0:
    #if "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=16443" in links:
    #    start=True
    #if start:
    #    downloadpocfile(id, links)
    #x.save()
    todo.append(x)

template=["id", "reference[]", "command", "===", "pocname", "stacktype", "isreproduced", "vuln_type", "stacktrace[]", "vuln_file", "===", "date", "author_username", "author_site", "fix", "note", "note2", "reproduced"]
# reference[]: delete useless links
# command: including binary and @@
# stacktype: asan or gdb
# isreproduced: if 1, stacktrace are generated from running PoC files, otherwise collected from webpage reports.
# stacktrace[]: this is a list, split by \n, limit to first 20 functions

# Interactively add detailed CVE data
# First, we auto download PoC files, open the reference site, generate a text file and open it for user edit
# Then, user will modify the text file, this script will add it to the db

def writetemplate(*args):
    id = args[0]
    pending_filepath = "cvedata/pending/"+id+".txt"
    fp = open(pending_filepath, "w", encoding="utf-8")
    for i, value in enumerate(args):
        key = template[i].replace("[]","")
        if isinstance(value, list):
            value = "\n".join([i.strip() for i in value if i.strip()])
        if not value:
            value = ""
        value = value.strip()
        if key == "===":
            fp.write("============\n")
        else:
            if not value:
                value = ""
            fp.write(f"~~{key}: {value}\n")
            if "\n" in value:
                fp.write("\n")
    fp.close()
    return pending_filepath

class CVE_gdb(TABLE):
    id = "" # CVE id
    isreproduced = -1
    vuln_type = ""
    stacktrace = "" # Limit to first 20 functions.
    vuln_file = ""
    poc_md5 = ""

class CVE_asan(CVE_gdb):
    pass

class CVE_extra(TABLE):
    id = ""
    reference = ""
    command = ""
    date = ""
    author_username = ""
    author_site = ""
    reproduced = -1
    poc_number = 0
    fix = ""
    note = ""
    note2 = ""

def readtemplate(id):
    # return [CVE_asans,...], CVE_extra
    pending_filepath = "cvedata/pending/"+id+".txt"
    datatmp = {} # temporary dict for CVE_asan or CVE_gdb
    objs_stacktrace, obj_extra = [], CVE_extra()
    obj_extra.id = id
    def savekv(key, value):
        if isinstance(value, str):
            value = value.strip()
        else:
            value = [v.strip() for v in value]
        nonlocal objs_stacktrace, obj_extra, datatmp
        key = key.lstrip("~")
        if key not in ["pocname", "stacktype", "isreproduced", "vuln_type", "stacktrace", "vuln_file"]:
            return setattr(obj_extra, key, value)
        if not key:
            return
        datatmp[key] = value
    def datatmp_done():
        nonlocal objs_stacktrace, obj_extra, datatmp, id
        if "stacktype" not in datatmp:
            return
        assert datatmp["stacktype"] in ["asan", "gdb"]
        if datatmp["stacktype"]=="asan":
            x = CVE_asan()
        else:
            x = CVE_gdb()
        #print(datatmp)
        x.id = id
        x.isreproduced = datatmp["isreproduced"]
        x.vuln_type = datatmp["vuln_type"]
        x.stacktrace = "###".join(datatmp["stacktrace"])
        x.vuln_file = datatmp["vuln_file"]
        x.poc_md5 = filemd5(POCFOLDER+"/pending/"+datatmp["pocname"])
        objs_stacktrace.append(x)
        datatmp = {}
        
    key, value = "", ""
    for line in open(pending_filepath, encoding="utf-8"):
        line = line.strip()
        if line.startswith("~~"):
            savekv(key, value)
            key, value = line.split(":",1)
        elif line.startswith("======"):
            savekv(key, value)
            datatmp_done()
        elif line:
            if not isinstance(value, list):
                value = [value]
            value.append(line)
        else:
            savekv(key, value)
    return objs_stacktrace, obj_extra

import webbrowser
def openbrowser(link):
    #return
    webbrowser.open(link, new=2)

def savetxt(id):
    os.rename("cvedata/pending/"+id+".txt", "cvedata/done/"+id+".txt")

from EasyLogin import EasyLogin
from config import el_params
a=EasyLogin(**el_params)
def gethtml(url, retry=3):
    try:
        return a.get(url, result=False, cache=True, o=True, allow_redirects=True).text
    except:
        if retry:
            return gethtml(url, retry=retry-1)
        else:
            raise

from utils import strip_tags, filemd5, getdomain
from pprint import pprint
from reportanalyzer import parse_gdb, parse_asan
import re
from poccrawler.githubissue import getissueowner
from poccrawler.bugzilla import getbugzillareporter

PRELOAD=False

if not PRELOAD:
    clearpending()
del(os.path.samefile) # Workaround for sshfs-win folder, see issue https://github.com/billziss-gh/sshfs-win/issues/162

data = sorted(todo, key=lambda i:str(i.id), reverse=True)
for i,x in enumerate(data):
  if os.path.isfile("cvedata/done/"+x.id+".txt"):
    continue
  try:
    print(f"[{i}/{len(todo)}] {x.id} {x.vuln_type_description} {x.vuln_func_description}")
    if i%5==0:
        toopen=[]
        for j in range(i, min(i+5, len(data))):
            links = data[j].useful_link.split("###")
            if not links:
                toopen.append("https://cve.mitre.org/cgi-bin/cvename.cgi?name="+data[j].id)
            for link in links:
                toopen.append(link)
        if input("open {} links? Enter n to skip".format(len(toopen))) not in ["n", "N"]:
            [openbrowser(i) for i in toopen]
    allhtml = ""
    author_username, author_site, fix = "", "", ""
    note, note2 = "", ""
    for link in x.useful_link.split("###"):
        if "/commit/" in link or "/pull/" in link or "/compare/" in link:
            fix = link
            continue
        if not link:
            continue
        print(link)
        allhtml += gethtml(link)
        if "github.com" in link and "/issues/" in link:
            author_username = getissueowner(link)
            author_site = "github"
        if "show_bug.cgi" in link:
            author_site = getdomain(link)
            author_username = getbugzillareporter(link)
    #continue # this is used to preload all html before manual work
    commands = []
    for line in allhtml.split("\n"):
        if "@@" in line or "$POC" in line or "Command" in line:
            commands.append(strip_tags(line).replace("$POC","@@"))
    #print(commands)
    if "AddressSanitizer" in allhtml:
        stacktype = "asan"
        stacks = parse_asan(strip_tags(allhtml))
    else:
        stacktype="gdb?"
        stacks = parse_gdb(strip_tags(allhtml))
    isreproduced = "-1"
    vuln_type = x.vuln_type_description
    
    stacktrace = []
    for stack in stacks:
        stacktrace.extend(stack)
    datestrs = re.findall(r"(\d\d\d\d-\d\d-\d\d)", allhtml)
    if datestrs:
        date = datestrs[0]
    else:
        date = ""
    downloadpocfile(x.id, x.useful_link.split("###"), writefile=not PRELOAD)
    if not PRELOAD:
        pending_filepath = writetemplate(x.id, x.useful_link.split("###"), commands, "===", "1", stacktype, isreproduced, vuln_type, stacktrace, x.vuln_file_description, "===", date, author_username, author_site, fix, note, note2, "-1")
        os.startfile(pending_filepath.replace("/", os.sep))
        while True:
            input("Enter when ready")
            try:
                objs_stacktrace, obj_extra = readtemplate(x.id)
                break
            except:
                traceback.print_exc()
        for i in objs_stacktrace:
            print(i.__dict__)
            i.save()
        print(obj_extra.__dict__)
        obj_extra.poc_number = pocfile_organize(x.project, x.id)
        obj_extra.save()
        
        savetxt(x.id)
  except:
    if not PRELOAD:
        raise
    traceback.print_exc()
    continue