#!/usr/bin/python
# -*- coding: utf-8 -*-

import time, os, http
from urllib.request import Request, build_opener, URLError, urlopen, HTTPError
from http.client import HTTPConnection
from lib import openanything

class Spider():
    """Class wich models the process of tree structure's discovery"""
    
    #Init method - Getter/Setter
    def __init__(self, domain, dictio='directories.jbrofuzz'):
        """Initialized with a Domain's object and a dictionary"""
        self.dictio='dic/'+dictio
        self.domain=domain

    def getDictio(self):
        return self.dictio

    def setDictio(self, dictio):
        self.dictio=dictio

    def readRobotsTxt(self, dom):
        """Method wich reads a possible robots.txt"""
        if (dom[:4] != 'http'):
            dom='http://' + dom
        try:
            f = urlopen(dom + '/robots.txt')
        except HTTPError as e:
            output='Robots.txt unreachable or absent : ' + str(e.code) + ' ' + e.reason 
            return output
        return (f.read().decode('utf-8'))

    def processDoublons(self, liste):
        """Processing of duplicate items in lists"""
        listeProcess = [] 
        listKey = []
        for i in liste:
            if i not in listeProcess:
                for key, value in i.items():
                    if (value in [200, 403]) and (key not in listKey):
                        listeProcess.append(i)
                        listKey.append(key)
        return listeProcess

    def codeFilter(self, dictResult, listeFiltered):
        """Filter operation of the HTTP's codes which interests us"""
        #print('Dict debut boucle')
        #print(dictResult)
        long=len(dictResult)
        for cle,valeur in dictResult.items():
            if (valeur in [200, 403]):
                #Removing possible Url's parameters
                symURL=['@','?','#']
                for sym in symURL:
                    indexF=cle.find(sym)
                    if (indexF != -1):
                        print("\n")
                        print('TRIGGER')
                        print(cle)
                        print(cle[:indexF])
                        dictResult[cle[:indexF]]=valeur
                        print('Dict avant del')
                        print(dictResult)
                        if (len(dictResult) != long):
                            del dictResult[cle]
                            print('Dict apres del')
                            print(dictResult)
                        cle=cle[:indexF]

                listeFiltered.append(dictResult)

    def processHttpError(self, opener, request, result, url):
        """Processing of errors from malformed's URL and 4** and 5** codes"""
        testDataStream=''
        try:
            testDataStream = opener.open(request)
        except (HTTPError, URLError, http.client.HTTPException, ConnectionResetError) as e:
            #If error, there's an issue with URL, we leave the method
            print('Fuck !')
            result[url]=503
            return result
        code=testDataStream.status
        #If we find 400 or 500 code, we have an HTTP's error
        if ((str(code))[0] == '4') or ((str(code))[0] == '5'):
            result[url]=code
            return result

    def requestBF(self, url):
        """Method which models structure tree's bruteforce's requests"""

        result={}
        requestInit=Request(url)

        #We delay between each requests to avoid sensitive IDS or antiDDOS
        time.sleep(2)

        #Possibility to make request more verboses if there's a problem
        HTTPConnection.debuglevel = 0

        #We instantiate our error handler and we provide it the request
        openerErr = build_opener(openanything.DefaultErrorHandler())
        self.processHttpError(openerErr, requestInit, result, url)
        if (result != {}):
            return result
        
        #Then, we instantiate our opener handling redirections and we provide it the request 
        openerRed = build_opener(openanything.SmartRedirectHandler())

        #Here 503 HTTP error not handled sometimes
        try:
            f = openerRed.open(requestInit)
            result[url]=f.status
        except (HTTPError, URLError, http.client.HTTPException, ConnectionResetError) as e:
            print('Fuck !')
            #print(e.code)
            result[url]=503
            return result
            

        #If redirection, we start over the process error+redirection on the new URL until we obtain HTTP's code 200
        if ((str(f.status))[0] == '3'):
            codeRedir=0
            while (codeRedir != 200):
                requestRedir=Request(f.newurl)
                self.processHttpError(openerErr, requestRedir, result, f.newurl)
                if (str(result[url])[0] == '4') or (str(result[url])[0] == '5'):
                    return result

                #Here 503 HTTP error not handled sometimes
                try:
                    fRedir = openerRed.open(requestRedir)
                    codeRedir=fRedir.status
                    result[f.newurl]=fRedir.status
                except (HTTPError, URLError, http.client.HTTPException, ConnectionResetError) as e:
                    print('Fuck !')
                    #print(e.code)
                    #codeRedir=e.code
                    result[f.newurl]=503
                    return result
        return result

    def processBFSpider(self, dom, dictio, listeFin):

        listTree=[]
        extFile=['.php', '.html', '.txt', '.sql', '.pdf', '.tar', '.gz', '.tar.gz', '.css', '.js', '.txt', '.asp', '.aspx', '.avi', '.bmp', '.bz', '.bz2', '.c', '.cc', '.cgi', '.conf', '.config', '.cp', '.py', '.csv', '.jpg', '.jpeg', '.png', '.mp3', '.mp4', '.divx', '.doc', '.docx', '.xls', '.xlsx', '.exe', '.swf', '.gif', '.htm', '.ico', '.inf', '.info', '.ini', '.iso', '.jar', '.jav', '.java', '.jsp', '.ksh', '.sh', '.bash', '.bat', '.bak', '.log', '.lua', '.mpeg', '.mpg', '.msf', '.odt', '.ova', '.ovf', '.pl', '.po', '.psd', '.rar', '.rb', '.rss', '.shtml', '.svg', '.ttf', '.vb', '.vdi', '.vmdk', '.wav', '.xhtml', '.xml', '.yml', '.zip', '.7z']
        with open(dictio, 'rb') as f:
            for line in f:
                try:
                    line=line.decode('utf-8')
                except UnicodeDecodeError:
                    continue
                #Dictionnary's commentary
                if (line[0] == '#'):
                    continue
                line=line.strip('\n')
                line=line.strip('\r')
                #If final list is not empty, This is not the first iteration on the domain
                if (listeFin != []):
                    for dictio in listeFin[-1]:
                        for url,code in dictio.items():
                            filename, file_ext=os.path.splitext(url)
                            if (code in [200, 403]) and (file_ext not in extFile):
                                #Detection of codes which interest us and files which may produce HTTP's code 200 infinitely
                                if (code == 200):
                                    #We check that previous url's segment is not a 403
                                    #If so, we don't launch requests, which may produce HTTP's code 200 infinitely
                                    tabUrl=(url.strip('/')).split('/')
                                    del tabUrl[-1]
                                    if (len(tabUrl) > 2):
                                        testUrl=tabUrl[0] + '//' + tabUrl[1] + ('/'.join(tabUrl[2:])) + '/'
                                        result=self.requestBF(testUrl)

                                        #A HTTP's error 403 produces always a dictionnary with 1 item
                                        if (len(result) == 1):
                                            if (result[testUrl] == 403):
                                                continue
                                if (url[-1] != '/'):
                                    url=url+'/'
                                print('Try: ' + url+line)
                                result=self.requestBF(url+line)
                                #print('***********************')
                                #print('Try: ' + url+line)
                                print(result)
                                #print('***********************')
                                self.codeFilter(result, listTree)
                            else:
                                continue
                else:
                    if (dom[-1] != '/'):
                        dom=dom+'/'
                    print('Try: ' + dom+line)
                    result=self.requestBF(dom+line)
                    #print('***********************')
                    #print('Try: ' + dom+line)
                    print(result)
                    #print('***********************')
                    self.codeFilter(result, listTree)

        listTree=self.processDoublons(listTree)
        return listTree

    def processSpider(self, listeFin, dom):
        """Method which bruteforces the tree structure of the Domain's object's url provided to the class, using dictionary provided to the class"""
        
        #listTree=[]
        #extFile=['.php', '.html', '.txt', '.sql', '.pdf', '.tar', '.gz', '.tar.gz', '.css', '.js', '.txt', '.asp', '.aspx', '.avi', '.bmp', '.bz', '.bz2', '.c', '.cc', '.cgi', '.conf', '.config', '.cp', '.py', '.csv', '.jpg', '.jpeg', '.png', '.mp3', '.mp4', '.divx', '.doc', '.docx', '.xls', '.xlsx', '.exe', '.swf', '.gif', '.htm', '.ico', '.inf', '.info', '.ini', '.iso', '.jar', '.jav', '.java', '.jsp', '.ksh', '.sh', '.bash', '.bat', '.bak', '.log', '.lua', '.mpeg', '.mpg', '.msf', '.odt', '.ova', '.ovf', '.pl', '.po', '.psd', '.rar', '.rb', '.rss', '.shtml', '.svg', '.ttf', '.vb', '.vdi', '.vmdk', '.wav', '.xhtml', '.xml', '.yml', '.zip', '.7z']

        #If necessary, we rewrite the target provided for urllib's format
        if (listeFin == []):
            
            #We check a possible domain's redirection on target (often redirect to www's subdomain)
            result=self.requestBF(dom)
            for cle,valeur in result.items():
                #If HTTP's code is 200 and result's list has more than one element, this is a redirection
                if (valeur == 200) and (len(result) > 1):
                    indexF=cle.find('?')
                    if (indexF != -1):
                        cle=cle[:indexF]
                    dom=cle
                    break

        listTree=self.processBFSpider(dom, self.dictio, listeFin)

        #We compare previous list with the actual to eliminate possible duplicate items
        if (listeFin != []):
            newListTree=[]
            for dictio in listTree:
                if dictio not in listeFin[-1]:
                    newListTree.append(dictio)
        else:
            newListTree=listTree
        return newListTree

    def processDepthSpider(self, depth):
        """Method which runs spider's process according to provided depth"""
        listTriFinal=[]
        i=0

        dom=self.domain.url
        if (dom[:6] != 'http://'):
            dom='http://' + self.domain.url
        if (dom[-1] != '/'):
            dom=dom + '/'
        while (i < depth):
            listTriFinal.append(self.processSpider(listTriFinal, dom))
            i += 1
        self.domain.setArbo(listTriFinal)
        print(listTriFinal)

