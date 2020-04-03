from .githubissue import getpocurls_githubissue
from .bugzilla import Bugzilla, AttachmentNotFound
from .gentoo import getpocurls_gentoo
from .bugschromium import getpocurls_bugschromium
bugzilla = Bugzilla()
import time
from EasyLogin import EasyLogin
from config import el_params, POCFOLDER
a=EasyLogin(**el_params)
import shutil
import os
from utils import filemd5
import traceback

POCPENDING=POCFOLDER+"/pending"

def clearpending(oldid=None):
    # move the pending folder to POCFOLDER/history/<oldid>
    if not oldid:
        try:
            shutil.rmtree(POCPENDING)
        except:
            pass
        os.makedirs(POCPENDING)
        return
    if os.path.isdir(POCFOLDER+"/history/"+oldid):
        oldid+="_"+str(int(time.time()))
    os.rename(POCPENDING, POCFOLDER+"/history/"+oldid)
    os.makedirs(POCPENDING)

def url2file(url, t, retry=3, cache=True, writefile=True):
    # download the url to pendingfolder, t is the filename(int)
    t = str(t)
    try:
        x = a.get(url, result=False, o=True, allow_redirects=True, cache=cache)
    except Exception as e:
        if retry:
            return url2file(url, t, retry=retry-1, writefile=writefile)
        else:
            print(f"[FAIL] {url} {e}")
            traceback.print_exc()
            #input("...")
            return False
    if x.status_code!=200 and "text/html" not in x.headers.get("content-type", ""):
        print(f"[FAIL] {x.status_code} {url}")
        return False
    if writefile:
        open(POCPENDING+"/"+t, "wb").write(x.content)
    return True

def downloadpocfile(cveid, links, writefile=True):
    res=[]
    for link in links:
        if "github.com" in link and "/issues/" in link:
            #print(link)
            res = getpocurls_githubissue(link)
            #print(res)
        elif "show_bug.cgi" in link:
            #print(link)
            domain = link.replace("https://","").replace("http://","").split("/")[0]
            res = bugzilla.get_attachments(link)
            #print(res)
        elif "blogs.gentoo.org" in link:
            #print(link)
            res = getpocurls_gentoo(link)
            #print(res)
        elif "code.google.com/p/chromium/issues" in link or "bugs.chromium.org/p/oss-fuzz/issues" in link:
            #print(link)
            res = getpocurls_bugschromium(link)
            #print(res)
        else:
            pass
            print("[unknown]", link)
    t=1
    if writefile:
        open(POCPENDING+"/"+cveid,"w").close()
    for item in res:
        if isinstance(item, list) or isinstance(item, tuple):
            url = item[1]
        else:
            url = item
        if "/blob/" in url:
            url = url + ("?raw=true" if "?" not in url else "&raw=true")
        if url2file(url, t, writefile=writefile):
            print("wget '{}' -O {}".format(url, t))
            t+=1

def pocfile_organize(prog, cveid):
    # After human work, copy files to byprog and bymd5, then call clearpending
    if not os.path.isdir(POCFOLDER+"/byprog/"+prog):
        os.makedirs(POCFOLDER+"/byprog/"+prog, exist_ok=True)
    assert os.path.isfile(POCPENDING+"/"+cveid)
    t=0
    for f in os.listdir(POCPENDING):
        if not f.isdigit():
            continue
        t+=1
        themd5 = filemd5(POCPENDING+"/"+f)
        print(f"{f}->{t} {themd5}")
        shutil.copy(POCPENDING+"/"+f, POCFOLDER+"/byprog/"+prog+"/"+cveid+"_"+str(t))
        shutil.copy(POCPENDING+"/"+f, POCFOLDER+"/bymd5/"+themd5)
    clearpending(cveid)
    return t