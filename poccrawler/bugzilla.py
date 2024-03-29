import sys
sys.path.append("..")
from EasyLogin import EasyLogin
from config import el_params
from utils import strip_tags
a = EasyLogin(**el_params)

def geturl(href, urlbase):
    if "://" in href:
        return href
    return urlbase+"/"+href

def callback(x):
    if x.status_code != 200:
        raise Exception("not 200")
    else:
        pass

class AttachmentNotFound(Exception):
    pass

class Bugzilla():
    def get(self, url, retry=3):
        global a
        try:
            res = a.get(url, o=True, cache=True, allow_redirects=True, callback=callback)
        except:
            if retry:
                print("[retry] ", url)
                return self.get(url, retry=retry-1)
            else:
                raise
        self.url = url
        self.urlbase = "/".join(url.split("/")[:-1])
        self.b = a.b
        self.html = res.text
        return res
    
    def get_attachments(self, url, filter_func=None):
        html = self.get(url).text
        b = self.b
        table = b.find(*self.att_table)
        if not table:
            if "Bug Access Denied" in html:
                print("[Bug Access Denied]", url)
                return []
            raise AttachmentNotFound(html)
        attachments = [(link.text.strip(), geturl(link["href"], self.urlbase)) for link in table.find_all(*self.att_link)]
        if filter_func:
            attachments = [i for i in attachments if filter_func(i)]
        return attachments
    
    def download_attachments(self, dest_folder, filter_func=None):
        pass
    
    def get_reporter(self):
        try:
            return strip_tags("<span" + self.html.split(" by <span")[1].split("</span>")[0])
        except:
            return ""
    
    def __init__(self, **args):
        self.att_table = ("table", {"id":"attachment_table"})
        self.att_link = ("a", {"title":"View the content of the attachment"})
        self.__dict__.update(args)

def getbugzillareporter(link):
    x = Bugzilla()
    x.get(link)
    return x.get_reporter()

if __name__ == "__main__":
    x = Bugzilla()
    x.get("https://bugzilla.redhat.com/show_bug.cgi?id=1494778")
    #print(x.download_attachments("libtiff"))
    print(x.get_reporter())