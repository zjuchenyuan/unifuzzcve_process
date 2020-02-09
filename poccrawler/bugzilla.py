from EasyLogin import EasyLogin
from config import el_params
a = EasyLogin(**el_params)

def geturl(href, urlbase):
    if "://" in href:
        return href
    return urlbase+"/"+href

class Bugzilla():
    def get(self, url):
        global a
        a.get(url, o=True, cache=True)
        self.url = url
        self.urlbase = "/".join(url.split("/")[:-1])
        self.b = a.b
    
    def download_attachments(self, dest_folder, filter_func=None):
        b = self.b
        table = b.find(*self.att_table)
        attachments = [(link.text, geturl(link["href"], self.urlbase)) for link in table.find_all(*self.att_link)]
        if filter_func:
            attachments = [i for i in attachments if filter_func(i)]
        
    
    def __init__(self, **args):
        self.att_table = ("table", {"id":"attachment_table"})
        self.att_link = ("a", {"title":"View the content of the attachment"})
        self.__dict__.update(args)

if __name__ == "__main__":
    x = Bugzilla()
    x.get("http://bugzilla.maptools.org/show_bug.cgi?id=2484")
    print(x.download_attachments("libtiff"))