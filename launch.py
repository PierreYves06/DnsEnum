#!/usr/bin/python
# -*- coding: utf-8 -*-

from dom.domain import *

def lectureAttr(liste):
    if liste == []:
        print 'Pas de réponse'
    else:
        for item in liste:
            print item

dom = 'google.com'
target = Domain(dom)
print 'Domaine cible : ' + target.getUrl()
dnsenum=Dnsenum(target)
dnsenum.processDig()
print "IP de la cible : "
lectureAttr(target.getIP())
print "Nameserver de la cible : "
lectureAttr(target.getNS())
print "Serveur mail de la cible : "
lectureAttr(target.getMX())
print "Enregistrement TXT de la cible : "
lectureAttr(target.getTXT())

print 'Reverse DNS de classe C en cours...'
dnsenum.processReverseDns()
print 'Resultat du reverse DNS de classe C : '
lectureAttr(target.getReverseDNS())

print 'Brute-force des sous domaines en cours... '
dnsenum.processBFSubDomain()
print 'Resultat du brute-force des sous domaines : '
for cle,valeur in (target.getSubDomain()).items():
    print 'IP(s) de ' + cle + ' :'
    lectureAttr(valeur)