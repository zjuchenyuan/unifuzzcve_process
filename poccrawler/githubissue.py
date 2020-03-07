from EasyLogin import EasyLogin
a = EasyLogin(cachedir="__pycache__", proxy="http://127.0.0.1:10802")
import re
_url_re = re.compile(r'(?im)((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\([^\s()<>]+\))+(?:\([^\s()<>]+\)|[^\s`!()\[\]{};:\'".,<>?]))')

def getissuetext(url):
    # return list of issue comments
    # apiurl = "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
    apiurl = url.replace("/github.com/", "/api.github.com/repos/")+"/comments"
    x = a.get(apiurl, result=False, o=True, cache=True).json()
    return [i["body"] for i in x]

def extracturls(text):
    return _url_re.findall(text)

def ispocurl(url):
    return "poc" in url

def getpocurls(url):
    return set([i for i in extracturls("\n".join(getissuetext(url))) if ispocurl(i)])

if __name__ == "__main__":
    from pprint import pprint
    pprint(getpocurls("https://github.com/Exiv2/exiv2/issues/428"))