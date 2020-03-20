from EasyLogin import EasyLogin
from config import el_params
a = EasyLogin(**el_params)


def callback(x):
    if x.status_code != 200:
        raise Exception("not 200")
    else:
        pass

def getpocurls_gentoo(url):
    x = a.get(url, o=True, cache=True, allow_redirects=True, callback=callback)
    res=[]
    for link in a.b.find_all("a"):
        if "https://github.com/asarubbo/poc" in link["href"]:
            res.append(link["href"])
    return res