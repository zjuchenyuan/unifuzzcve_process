from EasyLogin import EasyLogin
from config import el_params
a = EasyLogin(**el_params)
import json
import re

def callback(x):
    if x.status_code != 200:
        raise Exception("not 200")
    else:
        pass

def getpocurls_bugschromium(url):
    html = a.get(url, cache=True, allow_redirects=True)
    token = html.split(""" 'token': '""")[1].split("'")[0]
    
    id = url.split("id=")[1].split("#")[0].split("&")[0]
    apiurl = "https://bugs.chromium.org/prpc/monorail.Issues/ListComments"
    proj = url.split("/p/")[1].split("/")[0]
    
    postdata = '{"issueRef":{"localId":%s,"projectName":"%s"}}'%(id, proj)
    x = a.post(apiurl, postdata, cache=True, headers={"content-type": "application/json", "x-xsrf-token":token,"accept": "application/json"})
    res=[]
    #print(x.content)
    for comment in json.loads(x.text[5:])["comments"]:
        #print(comment)
        for attachment in comment.get("attachments",[]):
            res.append((attachment["filename"], "https://bugs.chromium.org/p/"+proj+"/issues/"+attachment["downloadUrl"]))
    if "oss-fuzz.com/download" in x.text:
        res.extend([("Reproducer_from_ossfuzz","https://oss-fuzz.com/download?testcase_id="+i) for i in re.findall(r"oss-fuzz\.com/download\?testcase_id=(\d+)", x.text)])
    return res