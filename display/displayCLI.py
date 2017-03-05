#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from threading import Thread
from dom.domain import *

class displayCLI(Thread):
	"""Classe qui modelise l'affichage en console"""

	
	def __init__(self, dom, dictio='directories.jbrofuzz'):
		"""
			Initialisation avec demarrage du thread gerant la boucle d affichage, 
			un objet Domain et un dictionnaire
		"""
		Thread.__init__(self)
		self.running = False
		if (dom[:6] == 'http://'):
			dom=dom[6:]
		self.target=Domain(dom)
		self.dictio=dictio

	def parseListeDictio(self, liste):
		"""Methode de lecture de la liste de dictionnaire"""
		if (isinstance(liste, str)):
			print(liste)
		else:
			for item in liste:
				for key,value in item.items():
					print(key + ' : ' + value)

	def processResponseYN(self, response):
		"""Methode qui traite les choix Oui/Non"""
		while (response != 'y') and (response != 'n'):
			print(choice + ' : Choix inconnu')
			response=input('Faites un nouveau choix svp (y/n) : ')
		if (response == 'y'):
			return True
		else:
			return False

	def lectureOtherResponse(self, dictio, type):
		"""Methode de lecture chelou"""
		for key,value in dictio.items():

			#Display ReverseDNS
			if (type=='RD'):
				print('IP : ' + key)
			else:
			#Display Brute-force subdomains
				print('Sous-domaine : ' + key)
			print('Resultat(s) : ')
			if (isinstance(value, str)):
				print(value)
			else:
				for item in value:
					print(item)

	def lectureDigResponse(self, liste):
		"""Methode de lecture des retours de dig"""
		if liste == []:
			print('Pas de réponse')
		else:
			if (isinstance(liste, str)):
				print(liste)
			else:
				print('Reponse : ')
				if (liste['ans'] == 'empty'):
					print('Pas de réponse')
				else:
					self.parseListeDictio(liste['ans'])

				print('Informations additionnelles : ')
				if (liste['add'] == 'empty'):
					print('Pas d\'informations additionnelles')
				else:
					self.parseListeDictio(liste['add'])

	def lectureSpiderResponse(self, liste):
		"""Methode de lecture des retours du Spider"""
		lvl=0
		for item in liste:
			lvl+=1
			print('Niveau de l\'arbo : ' + str(lvl))
			#print(item)
			for dictio in item:
				#print(dictio)
				for key,value in dictio.items():
					#print('Url : ' + key)
					#print('Code : ' + str(value))
					if (value == 200):
						print(key)

	def displayDnsEnum(self):
		"""Methode d'affichage de l'enumeration DNS"""
		print('IP de la cible : ')
		self.lectureDigResponse(self.target.getIP())
		print('Nameserver de la cible : ')
		self.lectureDigResponse(self.target.getNS())
		print('Serveur mail de la cible : ')
		self.lectureDigResponse(self.target.getMX())
		print('Enregistrement TXT de la cible : ')
		self.lectureDigResponse(self.target.getTXT())

	def enumSolo(self):
		"""Methode qui lance l'enumeration DNS"""
		dnsenum=Dnsenum(self.target, self.dictio)
		print('Enumeration DNS en cours...')
		dnsenum.processDig()
		print('Fait')
		self.displayDnsEnum()

		choice=input('Voulez vous effectuer un reverse DNS de classe C sur la cible ? (y/n) : ')
		resp=self.processResponseYN(choice)
		if (resp):
			print('Reverse DNS de classe C en cours...')
			dnsenum.processReverseDns()
			print('Fait')
			print('Resultat du reverse DNS de classe C :')
			self.lectureOtherResponse(self.target.getReverseDNS(), 'RD')
		else:
			print('Reverse DNS ignore')

		choice=input('Voulez vous effectuer un brute-force des sous-domaines sur la cible ? (y/n) : ')
		resp=self.processResponseYN(choice)
		if (resp):
			print('Dictionnaire utilise : ' + self.dictio)
			print('Brute-force des sous-domaines en cours...')
			dnsenum.processBFSubDomain()
			print('Resultat du brute-force des sous domaines : ')
			self.lectureOtherResponse(self.target.getSubDomain(), 'BF')
		else:
			print('Brute-force des sous-domaines ignore')

	def spiderSolo(self):
		"""Methode qui lance le Spider"""
		spider=Spider(self.target, self.dictio)
		print('Dictionnaire utilise : ' + self.dictio)
		print('Brute-force de l\'arborescence en cours... ')
		spider.processDepthSpider(4)
		self.lectureSpiderResponse(self.target.getArbo())

	def enumSpider(self):
		"""Methode qui lance l'enumeration DNS et le Spider"""
		print('EnumSpider')
		self.enumSolo()
		self.spiderSolo()

	def quitCLI(self):
		"""Methode qui arrete le thread et quitte le CLI"""
		print('Bye !')
		self.running = False

	def run(self):
		"""Methode run du Thread qui lance la boucle d'affichage"""
		options={'1': self.enumSolo,
					'2': self.spiderSolo,
					'3': self.enumSpider,
					'4': self.quitCLI,
		}
		self.running = True
		print('Bienvenue !')
		while self.running:
			print('Votre cible : ' + self.target.getUrl())
			print('Que désirez-vous faire ?\n1 - Enumeration DNS\n2 - Spider\n3 - Enumeration DNS + Spider\n4 - Exit')
			choice=input('Votre choix ? : ')
			try:
				options[choice]()
			except KeyError as e:
				print(choice + ' : Choix inconnu')
