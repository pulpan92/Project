import requests
from bs4 import BeautifulSoup as BS
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from multiprocessing import Process
import argparse

class checker:
    def get_method(self):
        bs = BS(self.body, "html.parser")
        link = bs.find_all("a", href=True)

        ori_query = urlparse(self.url).query
        if ori_query != "":
            temp_url = self.url
            ori_query_key = parse_qs(ori_query, keep_blank_values=True)
            ori_xss_payload = temp_url.replace(ori_query, urlencode({x: self.payload for x in ori_query_key}))
            res = self.sess.get(ori_xss_payload)
            print('[] GET method xss: ', ori_xss_payload)
            #print('[] ori xss payload: ', ori_xss_payload)
            if self.payload in res.text:
                print('[!] XSS detected: ', ori_xss_payload)


        for a in link:
            url = a["href"]

            if url.startswith("http://") is False or url.startswith("https://") is False or url.startswith("mailto:") is False:
                base = urljoin(self.url, url)
                #print('[] base: ', base)
                query = urlparse(base).query

                if query != "":
                    #xss_payload = query.replace(query[query.find('=')+1:len(query)], self.payload, 1)
                    query_key = parse_qs(query, keep_blank_values=True)
                    xss_payload = base.replace(query,urlencode({x: self.payload for x in query_key}))

                    res = self.sess.get(xss_payload)
                    print('[] GET method xss: ', xss_payload)
                    if self.payload in res.text:
                        print('[!] XSS detected: ', xss_payload)


    def post_method(self):
        bs = BS(self.body, "html.parser")
        forms = bs.find_all("form", method=True)

        for f in forms:
            try:
                act = f["action"]
            except KeyError:
                act = self.url

            if f["method"].lower().strip() == "post":
                keys = {}

                for key in f.find_all(["input", "textarea"]):
                    try:
                        keys.update({key["name"]:self.payload})
                    except Exception as e:
                        print('[!] Interneal error: ', str(e))
                req = self.sess.post(urljoin(self.url, act), data = keys)

                if self.payload in req.text:
                    print('[] payload exist: ', urljoin(self.url, req.url))


    def check(self, url, payload):
        self.url = url
        self.payload = payload
        self.sess = requests.Session()
        #print('[] url: ', url)

        try:
            sour = self.sess.get(url)
            self.body = sour.text
        except Exception as e:
            print('[!] Internal error: ', str(e))
            return 

        if sour.status_code > 400:
            print('[!] connection fail: ', str(sour.status_code))

        self.post_method(self)
        self.get_method(self)

class crawler:
    visited = []
    def getlink(self, base):
        li = []
        li.append(base)

        conn = requests.Session()
        text = conn.get(base).text
        hpar = BS(text, "html.parser")

        for obj in hpar.find_all("a", href=True):
            url = obj["href"]

            if url.startswith("http://") or url.startswith("https://"):
                continue
            elif urljoin(base, url) in self.visited:
                continue
            elif base == url:
                continue
            elif url.startswith('javascript:'):
                continue
            else:
                li.append(urljoin(base, url))
                self.visited.append(urljoin(base, url))

        return li

    def crawl(self, base, depth, payload):
        print("[] crawl base: ", base, " depth: ", depth, " payload: ", payload)
        url_li = self.getlink(base)
        #print('[] url list: ', url_li)

        for u in url_li:
            p = Process(target=checker.check, args=(checker, u, payload))
            p.start()
            p.join()

            if int(depth) != 0:
                self.crawl(u, int(depth)-1, payload)
            else:
                break


def st():
    parse = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    pos_opt = parse.add_argument_group("option")
    pos_opt.add_argument("-u", metavar = "")
    pos_opt.add_argument("-d", metavar = "", default = 2)
    pos_opt.add_argument("-p", metavar = "", default = "\"'`>")
    opt = parse.parse_args()

    c = crawler()
    c.crawl(opt.u, opt.d, opt.p)
    

if __name__ == '__main__':
    st()
