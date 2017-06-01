#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup

class GatherInfos():
    """Class dedicated to gathering informations"""

    #Init method - Getters/Setters
    def __init__(self, domain):
        "Initialized with a Domain's object"
        self.domain=domain

    def getNetcraftInfos(self):
        listInfos=[]
        r = requests.get('http://toolbar.netcraft.com/site_report?url=' + self.domain.getUrl())
        soup = BeautifulSoup(r.text, 'html.parser')
        reportSections=soup.find_all('section', attrs={'class':'site_report_table'})

        for report in reportSections:
            dictInfos = {}
            lines1=report.find_all('tr', attrs={'class':'TBtr'})
            #print(lines1)
            #input('Press a key')
            lines2=report.find_all('tr', attrs={'class':'TBtr2'})
            #print(lines2)
            #input('Press a key')
            lines=lines1+lines2
            for line in lines:
                titlesTag=line.find_all('th')
                contentsTag=line.find_all('td')
                i=0
                for title in titlesTag:
                    dictInfos[title.get_text()]=(contentsTag[i]).get_text()
                    #print(title.get_text())
                    #print((contentsTag[i]).get_text())
                    i+=1
                    #input('Press a key')
                #long=len(titles)
                #i=0
                #while (i < long):
                    
                #input('Press a key')
            listInfos.append(dictInfos)

        self.domain.setInfos(listInfos)
