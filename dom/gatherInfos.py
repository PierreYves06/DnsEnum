#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests, subprocess, shlex
from bs4 import BeautifulSoup

class GatherInfos():
    """Class dedicated to gathering informations"""

    #Init method - Getters/Setters
    def __init__(self, domain):
        "Initialized with a Domain's object"
        self.domain=domain

    def tagToString(self, list):
        stringList=[]
        for item in list:
            stringList.append(item.get_text())
        return stringList

    def execCmd(self, cmd):
        "Execute a command and return error if necessary"
        args=shlex.split(cmd)
        p=subprocess.Popen(args, stderr=subprocess.PIPE)
        err=p.stderr.read().decode('utf-8')
        return err

    def getNetcraftInfos(self):
        listInfos=[]
        r = requests.get('http://toolbar.netcraft.com/site_report?url=' + self.domain.getUrl())
        soup = BeautifulSoup(r.text, 'html.parser')
        reportSections=soup.find_all('section', attrs={'class':'site_report_table'})

        for report in reportSections:
            dictInfos = {}
            lines1=report.find_all('tr', attrs={'class':'TBtr'})
            lines2=report.find_all('tr', attrs={'class':'TBtr2'})
            lines=lines1+lines2
            for line in lines:
                titlesTag=line.find_all('th')
                contentsTag=line.find_all('td')
                i=0
                for title in titlesTag:
                    dictInfos[title.get_text()]=(contentsTag[i]).get_text()
                    i+=1
                    #input('Press a key')
            if dictInfos != {}:
                listInfos.append(dictInfos)

        for report in reportSections:
            dictInfos = {}
            listLines=[]
            #lines=report.find_all('tr', attrs={'class':'TBtrtitle'})
            lines=report.find_all('thead')
            for line in lines:
                titlesTag=line.find_all('th')
                allContentsTag=line.find_next('tbody')
                titlesTag=self.tagToString(titlesTag)
                titlesTagKey='\t'.join(titlesTag)
                #print(titlesTag)
                #print(contentsTag)
                lines1=allContentsTag.find_all('tr', attrs={'class':'TBtr'})
                lines2=allContentsTag.find_all('tr', attrs={'class':'TBtr2'})
                lines=lines1+lines2
                for line in lines:
                    contentsTag=line.find_all('td')
                    contentsTag=self.tagToString(contentsTag)
                    #print(titlesTag)
                    #print(contentsTag)
                    #input('Press a key')
                    listLines.append(contentsTag)
                #print(listLines)
                dictInfos[titlesTagKey]=listLines
            if dictInfos != {}:
                listInfos.append(dictInfos)    

        self.domain.setInfos(listInfos)

    def whoisProcess(self):
        output=subprocess.check_output('whois ' + self.domain.getUrl(), shell=True)
        return output
        #if output != '':
            #print('Error : ' + output)
        
