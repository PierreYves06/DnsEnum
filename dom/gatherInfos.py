#!/usr/bin/python
# -*- coding: utf-8 -*-

class GatherInfos():
    """Class dedicated to gathering informations"""

    #Init method - Getters/Setters
    def __init__(self, domain):
        "Initialized with a Domain's object"
        self.domain=domain

    def getNetcraftInfos(self):
        self.domain.setInfos('Netcraft ! ' + self.domain.getUrl())
