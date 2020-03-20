from .githubissue import getpocurls_githubissue
from .bugzilla import Bugzilla, AttachmentNotFound
from .gentoo import getpocurls_gentoo
bugzilla = Bugzilla()
def downloadpocfile(cveid, links):
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
        else:
            pass
            print(link)
