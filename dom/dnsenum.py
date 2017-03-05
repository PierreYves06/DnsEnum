#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess, os, sys
import os, sys

class Dnsenum():
    "Classe qui modelise le processus de decouverte des sous-domaines"

    #Methode init - Getters/Setters
    def __init__(self, domain, dictio='directories.jbrofuzz'):
        "Initialisee avec un objet Domain et un dictionnaire"
        self.dictio='dic/'+dictio
        self.domain=domain

    def getDictio(self):
        return self.dictio

    def setDictio(self, dictio):
        self.dictio=dictio

    def processLine(self, line):
        listLine=[]
        line = line.strip('\n')
        tabLine = line.split('\t')
        if (tabLine[-1] != ''):
            return tabLine[-1]

    def assignInfos(self, result):
        "Methode qui assigne les infos aux divers enregistrements du dictionnaire retourne par la classe"
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
        "Methode qui parse le tableau envoye par readOutput()"
        listSearch = []
        for (i, item) in enumerate(tab):
            test=item.find(string)
            if (test != -1):
                if (count > 1):
                    #Le tableau contient plus d'un resultat, on itere par rapport a count
                    for j in range(1,count+1) :
                        response = tab[i+j]
                        listSearch.append(response)
                else:
                    #Un seul resultat, on l extrait et on le retourne
                    response = tab[i+1]
                    return response

        return listSearch

    def searchInFos(self, tab):
        "Methode qui extrait les infos de la reponse envoye par dig"
        dictSearch = {}

        #On parse une premiere fois pour decouper la reponse en section
        string = '->>HEADER<<-'
        response = self.parseTab(tab, string)
        tabResponse = response.split(',')
        testAns = int(tabResponse[1][-1])
        testAdd = int(tabResponse[3][-2])
        if (testAns != 0):

            #On recupere les infos de la section ANSWER
            string = 'ANSWER SECTION'
            response = self.parseTab(tab, string, testAns)
            dictSearch['ans'] = response
        if (testAdd != 0):

            #On recupere les infos de la section ADDITIONAL eventuellement
            string = 'ADDITIONAL SECTION'
            response = self.parseTab(tab, string, testAdd)
            dictSearch['add'] = response
        return dictSearch

    def readOutput(self, output):
        "Methode qui recupere la sortie de dig et la traite selon les cas"
        f = open('tmp.txt', 'w')
        f.write(output.decode('utf-8'))
        f.close()
        f = open('tmp.txt', 'r')
        tabLines=f.readlines()
        f.close()

        #Envoi vers la methode searchInfos pour extraction des infos
        infos = self.searchInFos(tabLines)
        
        #Si pas de reponse
        if (infos == {'add': []}):
            infos = 'No answer'
            subprocess.check_output(["rm", "tmp.txt"])
            return infos
        subprocess.check_output(["rm", "tmp.txt"])
        return infos

    def extractIP(self, info):
        "Methode pour extraire les IP des enregitrements supplementaire (NS, MX, etc...)"
        outputIP=subprocess.check_output('dig ' + info, shell=True)
        resultIP=self.readOutput(outputIP)
        resultIP=(self.processLine(resultIP['ans']))
        return resultIP
                

    def processDig(self):
        "Methode de lancement des operations dig de base"
        allResult={}

        #On recupere les sorties de la commande dig effectue sur l url de l objet Domain passe a la classe
        outputG=subprocess.check_output('dig ' + self.domain.url, shell=True)
        outputNS=subprocess.check_output('dig ' + self.domain.url + ' ns', shell=True)
        outputMX=subprocess.check_output('dig ' + self.domain.url + ' mx', shell=True)
        outputTXT=subprocess.check_output('dig ' + self.domain.url + ' txt', shell=True)

        #On traite les sorties avec les methodes dediees
        resultG=self.readOutput(outputG)
        resultNS=self.readOutput(outputNS)
        resultMX=self.readOutput(outputMX)
        resultTXT=self.readOutput(outputTXT)

        #On extrait les resultats et on les assignent à l'objet Domain passe a la classe

        #Resultat General
        if (resultG != 'No answer'):
            infosG=self.assignInfos(resultG)
            self.domain.setIP(infosG['ans'])
        else:
            self.domain.setIP('No answer')

        #Resultat Nameserver
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

        #Resultat MX
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

		#Resultat TXT
        if (resultTXT != 'No answer'):
            infosTXT=self.assignInfos(resultTXT)
            self.domain.setTXT(infosTXT)
        else:
            self.domain.setTXT('No answer')
    
    def processReverseDns(self):
        "Methode qui effectue une recherche en reverse DNS sur le sous reseau de classe C de l'IP du domaine"
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

    def processBFSubDomain(self):
        "Methode de brute force des sous-domaines eventuels base sur un dictionnaire"
        dictBFSubDom={}
        with open(self.dictio, 'rb') as f:
            for line in f:
                try:
                    line=line.decode('utf-8')
                except UnicodeDecodeError:
                    #print('UnicodeDecodeError')
                    #input()
                    continue
                if (line[0] == '#'):
                    continue
                tryBF=line.strip('\n')
                print(tryBF)
                try:
                    outputtryBF=subprocess.check_output('dig ' + tryBF + '.' + self.domain.url, stderr=subprocess.STDOUT, shell=True)
                except:
                    #print('Erreur Brute Force')
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
            self.domain.setSubDomain(dictBFSubDom)
