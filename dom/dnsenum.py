#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess, os, sys

class Dnsenum():
    "Classe qui modelise les differents processus de reconanissance liés a dig"

    #Methode init - Getters/Setters
    def __init__(self, domain, dictio='directories.jbrofuzz'):
        "Initialisee avec un objet Domain et un dictionnaire"
        self.dictio='dic/'+dictio
        self.domain=domain

    def getDictio(self):
        return self.dictio

    def setDictio(self, dictio):
        self.dictio=dictio

    def processDig(self):
        "Methode de lancement des operations dig de base (Enregistrements IP, NS, MX et TXT)"

        #On recupere les sorties de la commande dig effectue sur l url de l objet Domain passe a la classe
        #l'option +short de dig permet de recuperer les infos essentielles
        outputIP=subprocess.check_output('dig ' + self.domain.url + ' +short', shell=True)
        outputNS=subprocess.check_output('dig ns ' + self.domain.url + ' +short', shell=True)
        outputMX=subprocess.check_output('dig mx ' + self.domain.url + ' +short', shell=True)
        outputTXT=subprocess.check_output('dig txt ' + self.domain.url + ' +short', shell=True)

        #On stocke les resultat lignes à lignes dans des listes
        listeIP=(outputIP.split('\n'))[:-1]
        listeNS=(outputNS.split('\n'))[:-1]
        listeMX=(outputMX.split('\n'))[:-1]
        listeTXT=(outputTXT.split('\n'))[:-1]

        #On attribue ces listes aux différents attributs de l'objet de classe Domain
        self.domain.setIP(listeIP)
        self.domain.setNS(listeNS)
        self.domain.setMX(listeMX)
        self.domain.setTXT(listeTXT)

    def processReverseDns(self):
        "Methode qui effectue une recherche en reverse DNS sur le sous reseau de classe C de l'IP du domaine"
        listeRev=[]

        #On recupere une des IP du domaine
        IP=(self.domain.getIP())[0]

        #On extrait le reseau de classe C de cette IP
        network='.'.join((IP.split('.'))[0:-1])
        #host=(IP.split('.'))[-1]

        #On lance une boucle pour tester tous les hotes de 1 a 254
        tryHost=1
        while (tryHost < 255):

            #L'option -x de dig permet de retrouver un nom de domaine par rapport a une IP
            outputRev=subprocess.check_output('dig -x ' + network + '.' + str(tryHost) + ' +short', shell=True)
            if outputRev != '':

                #On remplit une liste avec les resultats positifs
                listeRev.append(network + '.' + str(tryHost) + ' : ' + outputRev[:-1])
            
            tryHost+=1

        #On attribue cette liste a l'objet de classe Domain
        self.domain.setReverseDNS(listeRev)

    def processBFSubDomain(self):
        "Methode de brute force des sous-domaines eventuels base sur un dictionnaire"
        dictioBFSubDom = {}

        # On ouvre et on parcourt le dictionnaire ligne a ligne
        with open(self.dictio, 'r') as f:
            for line in f:

                #On passe les lignes de commentaires
                if (line[0] == '#'):
                    continue
                try:

                    #On recupere l(es)'IP eventuelle d'un sous domaine et on les stocke dans un dictionnaire
                    outputtryBF=subprocess.check_output('dig ' + line[:-1] + '.' + self.domain.url + ' +short', stderr=subprocess.STDOUT, shell=True)
                    if outputtryBF != '':
                        listBFSubDom = (outputtryBF.split('\n'))[:-1]
                        dictioBFSubDom[line[:-1] + '.' + self.domain.url] = listBFSubDom

                #Certains caracteres des dictionnaires peuvent faire planter dig
                #On recupere l erreur dans ce cas
                except subprocess.CalledProcessError:
                    #print 'Probleme dans l execution de dig'
                    pass

        #On attribue ce dictionnaire à l'objet de classe Domain
        self.domain.setSubDomain(dictioBFSubDom)