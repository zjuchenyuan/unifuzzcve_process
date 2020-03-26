from EasyLogin import EasyLogin
from config import githubusername, githubtoken
a = EasyLogin(cachedir="__pycache__", proxy="http://127.0.0.1:10802")
import re
_url_re = re.compile(r'(?im)((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\([^\s()<>]+\))+(?:\([^\s()<>]+\)|[^\s`!()\[\]{};:\'".,<>?]))')

def getissuetext(url):
    # return list of issue comments
    # apiurl = "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
    res = []
    apiurl = url.replace("/github.com/", "/api.github.com/repos/")
    x = a.get(apiurl, result=False, o=True, cache=True, failstring="API rate limit exceeded", auth=(githubusername, githubtoken)).json()
    res.append(x["body"])
    apiurl = url.replace("/github.com/", "/api.github.com/repos/")+"/comments"
    x = a.get(apiurl, result=False, o=True, cache=True, failstring="API rate limit exceeded", auth=(githubusername, githubtoken)).json()
    res.extend(i["body"] for i in x)
    #print(res)
    return res

def extracturls(text):
    #print(text)
    return _url_re.findall(text)

def ispocurl(url):
    #print(url)
    return "poc" in url or "?raw=true" in url

def getpocurls_githubissue(url):
    return set([i for i in extracturls("\n".join(getissuetext(url))) if ispocurl(i)])

def getissueowner(url):
    apiurl = url.replace("/github.com/", "/api.github.com/repos/")
    x = a.get(apiurl, result=False, o=True, cache=True, failstring="API rate limit exceeded", auth=(githubusername, githubtoken)).json()
    return x["user"]["login"]

if __name__ == "__main__":
    from pprint import pprint
    pprint(getpocurls_githubissue("https://github.com/Exiv2/exiv2/issues/712"))