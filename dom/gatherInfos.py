#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from lib.customHtmlParser import CustomHtmlParser


class GatherInfos():
    """Class dedicated to gathering informations"""

    #Init method - Getters/Setters
    def __init__(self, domain):
        "Initialized with a Domain's object"
        self.domain=domain

    def getNetcraftInfos(self):
        r = requests.get('https://searchdns.netcraft.com/?host=' + self.domain.getUrl())
        
        self.domain.setInfos(r.text)
        parser = CustomHtmlParser()
        parser.feed(r.text)
