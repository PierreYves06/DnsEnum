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
        r = requests.get('http://toolbar.netcraft.com/site_report?url=' + self.domain.getUrl())
        soup = BeautifulSoup(r.text, 'html.parser')
        reportSections=soup.find_all('section', attrs={'class':'site_report_table'})
        #lineReports=reportSections.find('tr', attrs={'class':'TBtr2'})
        #reportsLines = reportSections.find_all('tr', attrs={'class':'TBtr2'})
        #print(reportsLines)
        for report in reportSections:
            print(report.findAll('tr', attrs={'class':'TBtr'}))
            print(report.findAll('tr', attrs={'class':'TBtr2'}))
            input('Press a key')
        #print(reportSections)
        #for section in reportSections:
        #    print(section.get('class')) 

        self.domain.setInfos(reportSections)
