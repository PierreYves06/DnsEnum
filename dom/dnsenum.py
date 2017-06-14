#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess, os, sys, math
import os, sys
import threading
from random import *

class Dnsenum():
    """Class which models discovery's process of subdomains"""

    #Init method - Getters/Setters
    def __init__(self, domain, dictio='directories.jbrofuzz'):
        "Initialized with a Domain's object and a dictionary"
        self.dictio='dic/'+dictio
        self.domain=domain
        self.chunkSubDom=[]

    def getDictio(self):
        return self.dictio

    def setDictio(self, dictio):
        self.dictio=dictio

    def processLine(self, line):
        """Method which parses results's line of requests"""
        listLine=[]
        line = line.strip('\n')
        tabLine = line.split('\t')
        if (tabLine[-1] != ''):
            return tabLine[-1]

    def assignInfos(self, result):
        "Method which assigns informations to various dictionary's recordings returned by the class"
        dictInfos={}
        if (isinstance(result['ans'], str)):
            dictInfos['ans']=self.processLine(result['ans'])
        else:
            dictInfos['ans']=[]
            for item in result['ans']:
                dictInfos['ans'].append(self.processLine(item))

        if ((hasattr(result,'add')) and (result['add'] != [])):
            if (isinstance(result['add'], str)):
                dictInfos['add']=self.processLine(result['add'])
            else:
                dictInfos['add']=[]
            for item in result['add']:
                dictInfos['add'].append(self.processLine(item))
        else:
            dictInfos['add']='empty'
                
        return dictInfos

    def parseTab(self, tab, string, count=1):
        "Method which parses la liste sent by readOutput()"
        listSearch = []
        for (i, item) in enumerate(tab):
            test=item.find(string)
            if (test != -1):
                if (count > 1):
                    #If the list contains more than one result, we iterate on count
                    for j in range(1,count+1) :
                        response = tab[i+j]
                        listSearch.append(response)
                else:
                    #One result, we extract and return it
                    response = tab[i+1]
                    return response

        return listSearch

    def searchInFos(self, tab):
        "Methode which extracts response's informations sent by dig"
        dictSearch = {}

        #We parse a first-timer to cut answer in section
        string = '->>HEADER<<-'
        response = self.parseTab(tab, string)
        tabResponse = response.split(',')
        testAns = int(tabResponse[1][-1])
        testAdd = int(tabResponse[3][-2])
        if (testAns != 0):

            #We retrieve informations ANSWER's section
            string = 'ANSWER SECTION'
            response = self.parseTab(tab, string, testAns)
            dictSearch['ans'] = response
        if (testAdd != 0):

            #We retrieve informations ADDITIONALs section, eventually
            string = 'ADDITIONAL SECTION'
            response = self.parseTab(tab, string, testAdd)
            dictSearch['add'] = response
        return dictSearch

    def readOutput(self, output):
        "Method which retrieves dig's output and deals with according to the case"
        nameFile=str(random())[2:]
        f = open(nameFile, 'w')
        f.write(output.decode('utf-8'))
        f.close()
        f = open(nameFile, 'r')
        tabLines=f.readlines()
        f.close()

        #Sending to searchInfos's method, to extract informations
        infos = self.searchInFos(tabLines)
        
        #If no answer
        if (infos == {'add': []}):
            infos = 'No answer'
            subprocess.check_output(["rm", nameFile])
            return infos
        subprocess.check_output(["rm", nameFile])
        return infos

    def extractIP(self, info):
        "Method which extract IPs of the additional recordings (NS, MX, etc...)"
        outputIP=subprocess.check_output('dig ' + info, shell=True)
        resultIP=self.readOutput(outputIP)
        resultIP=(self.processLine(resultIP['ans']))
        return resultIP
                

    def processDig(self):
        "Method which launches basic dig's operations"
        allResult={}

        #We retrieve outputs of dig's command, applyied to url of the Domain's object provided to the class
        outputG=subprocess.check_output('dig ' + self.domain.url, shell=True)
        outputNS=subprocess.check_output('dig ' + self.domain.url + ' ns', shell=True)
        outputMX=subprocess.check_output('dig ' + self.domain.url + ' mx', shell=True)
        outputTXT=subprocess.check_output('dig ' + self.domain.url + ' txt', shell=True)

        #We process output with the dedicated methods
        resultG=self.readOutput(outputG)
        resultNS=self.readOutput(outputNS)
        resultMX=self.readOutput(outputMX)
        resultTXT=self.readOutput(outputTXT)

        #We extract results and on assigned them to the Domain's object provided to the class

        #General result
        if (resultG != 'No answer'):
            infosG=self.assignInfos(resultG)
            self.domain.setIP(infosG['ans'])
        else:
            self.domain.setIP('No answer')

        #Nameserver result
        if (resultNS != 'No answer'):
            infosNS=self.assignInfos(resultNS)
            if (isinstance(infosNS['ans'], str)):
                IP_NS=self.extractIP(infosNS['ans'])
                fulldict={}
                fulldict[infosNS['ans']]=IP_NS
                infosNS['ans']=fulldict
            else:
                listFullDict=[]
                for name in infosNS['ans']:
                    IP_NS=self.extractIP(name)
                    fulldict={}
                    fulldict[name]=IP_NS
                    listFullDict.append(fulldict)
                infosNS['ans']=listFullDict
            self.domain.setNS(infosNS)
        else:
            self.domain.setNS('No answer')

        #MX result
        if (resultMX != 'No answer'):
            infosMX=self.assignInfos(resultMX)
            if (isinstance(infosMX['ans'], str)):
                tabName=name.split(' ')
                chunk=tabName[-1]
                IP_MX=self.extractIP(chunk)
                fulldict={}
                fulldict[infosMX['ans']]=IP_MX
                infosMX['ans']=fulldict
            else:
                listFullDict=[]
                for name in infosMX['ans']:
                    tabName=name.split(' ')
                    chunk=tabName[-1]
                    IP_MX=self.extractIP(chunk)
                    fulldict={}
                    fulldict[name]=IP_MX
                    listFullDict.append(fulldict)
                infosMX['ans']=listFullDict
            self.domain.setMX(infosMX)
        else:
            self.domain.setMX('No answer')

		#TXT result
        if (resultTXT != 'No answer'):
            infosTXT=self.assignInfos(resultTXT)
            self.domain.setTXT(infosTXT)
        else:
            self.domain.setTXT('No answer')
    
    def processReverseDns(self):
        "Method which performs a reverse DNS's research on the C class's subnetwork of the domain's IP"
        IP=self.domain.getIP()
        dictRevDNS={}
        width = len(IP)
        if (width >= 10):
            index = IP.find('.', -4)
        else:
            index = IP.find('.', -2)
        index = width-index-1
        IP = IP[:-index]
        host = 0
        while ( host < 255):
            outputRev=subprocess.check_output('dig -x ' + IP + str(host), shell=True)
            resultRev=self.readOutput(outputRev)
            if ((resultRev != 'No answer') and (resultRev != {})):
                if isinstance(resultRev['ans'], str):
                    match=self.processLine(resultRev['ans'])
                    dictRevDNS[IP + str(host)]=match
                else:
                    listRevDNS=[]
                    for item in resultRev['ans']:
                        match=self.processLine(item)
                        listRevDNS.append(match)
                    dictRevDNS[IP + str(host)]=listRevDNS
            host+=1
        self.domain.setReverseDNS(dictRevDNS)

    def processBFSubDomain(self, dictio):
        "Method to bruteforce possible subdomains, based on a dictionary"
        dictBFSubDom={}

        with open(dictio, 'rb') as f:
            for line in f:
                try:
                    line=line.decode('utf-8')
                except UnicodeDecodeError:
                    continue
                if (line[0] == '#'):
                    continue
                tryBF=line.strip('\n')
                testSp=tryBF.find(' ')
                if (testSp != -1):
                    continue
                try:
                    outputtryBF=subprocess.check_output('dig ' + tryBF + '.' + self.domain.url, stderr=subprocess.STDOUT, shell=True)
                except:
                    continue
                resultTryBF=self.readOutput(outputtryBF)
                if (resultTryBF != 'No answer'):
                    if isinstance(resultTryBF['ans'], str):
                        match=self.processLine(resultTryBF['ans'])
                        dictBFSubDom[tryBF + '.' + self.domain.url]=match
                    else:
                        listBFSubDom=[]
                        for item in resultTryBF['ans']:
                            match=self.processLine(item)
                            listBFSubDom.append(match)
                        dictBFSubDom[tryBF + '.' + self.domain.url]=listBFSubDom
            f.close()
            self.chunkSubDom.append(dictBFSubDom)

    def launchThreadBF(self):
        fd=open(self.dictio, 'rb')
        n=0
        for line in fd:
            n+=1
        fd.close()
        print(n)
        l=round(n/2)
        #r=n%2
        print(l)
        fd1=open('dic/dic1', 'wb')
        fd2=open('dic/dic2', 'wb')
        fd3=open(self.dictio, 'rb')
        i=1
        for line in fd3:
            print(line)
            if (i < l):
                print('fd1')
                fd1.write(line)
            else:
                print('fd2')
                fd2.write(line)
            i+=1
        input('Press a key')
        dictFinalBFSubDom={}
        t1=threading.Thread(None, self.processBFSubDomain, None, ('dic/dic1',))
        t2=threading.Thread(None, self.processBFSubDomain, None, ('dic/dic2',))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        for item in self.chunkSubDom:
            for key,value in item.items():
                dictFinalBFSubDom[key]=value
        self.domain.setSubDomain(dictFinalBFSubDom)
        subprocess.check_output(["rm", "dic/dic1"])
        subprocess.check_output(["rm", "dic/dic2"])
