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
        self.domain.setInfos(soup.prettify())
