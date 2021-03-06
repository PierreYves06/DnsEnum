#!/usr/bin/python
# -*- coding: utf-8 -*-

from dom.dnsenum import *
from dom.spider import *
from dom.gatherInfos import *

class Domain:
    "Class which models a domain and possible operations on it"
    def __init__(self, url):
        self.url = url

    def getUrl(self):
        return self.url

    def setUrl(self, url):
        self.url=url

    def getIP(self):
        return self.IP

    def setIP(self, IP):
        self.IP=IP

    def getNS(self):
        return self.NS

    def setNS(self, NS):
        self.NS=NS

    def getMX(self):
        return self.MX

    def setMX(self, MX):
        self.MX=MX

    def getTXT(self):
        return self.TXT

    def setTXT(self, TXT):
        self.TXT=TXT

    def getReverseDNS(self):
        return self.reverseDNS

    def setReverseDNS(self, reverseDNS):
        self.reverseDNS=reverseDNS

    def getSubDomain(self):
        return self.subDomain

    def setSubDomain(self, subDomain):
        self.subDomain=subDomain

    def setArbo(self, arbo):
        self.arbo=arbo

    def getArbo(self):
        return self.arbo

    def setInfos(self, infos):
        self.infos=infos

    def getInfos(self):
        return self.infos
