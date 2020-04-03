from html.parser import HTMLParser

class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.strict = False
        self.convert_charrefs= True
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()

import hashlib
def filemd5(filepath):
    return hashlib.md5(open(filepath, "rb").read()).hexdigest()

from urllib.parse import urlparse
def getdomain(link):
    return urlparse(link).netloc