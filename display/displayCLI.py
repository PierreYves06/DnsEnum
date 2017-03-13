#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys, time, os
from threading import Thread
from dom.domain import *

class displayCLI(Thread):
	"""Classe qui modelise l'affichage en console"""

	
	def __init__(self, args, dictio='directories.jbrofuzz', depth=2):
		"""
			Initialisation avec demarrage du thread gerant la boucle d affichage, 
			un objet Domain et un dictionnaire
		"""
		#print(args)
		Thread.__init__(self)
		self.running = False
		dom=args['DOMAIN']
		if (dom[:6] == 'http://'):
			dom=dom[6:]
		self.target=Domain(dom)
		if (args['-d']):
			self.dictio=args['-d']
		else:
			self.dictio=dictio
		if (args['--depth']):
			self.depth=int(args['--depth'])
		else:
			self.depth=depth
		self.args=args

	def writeResult(self, file, output):
		"""Methode d ecriture des resultats dans un fichier"""
		if (os.path.exists(file)):
			print('Il y a deja un fichier avec ce nom !')
			choice=input('Voulez-vous remplace ce fichier ? (y/n) : ')
			resp=self.processResponseYN(choice)
			if (resp):
				f=open(file, 'w')
				f.write(output)
				f.close()
			else:
				print('Operation ignoree')
		else:
			f=open(file, 'w')
			f.write(output)
			f.close()

	def decoratorTimerProcess(process):
		"""Decorateur ajoutant un timer a un process"""
		def timerProcess(self):
			start=time.time()
			process(self)
			interval=time.time() - start
			print('\nTemps d execution : ' + str(round(interval, 2)) + ' sec.')
		return timerProcess

	def parseListeDictio(self, liste):
		"""Methode de lecture de la liste de dictionnaire"""
		#print(liste)
		if (isinstance(liste, str)):
			print(liste.strip('"'))
		else:
			for item in liste:
				if (isinstance(item, str)):
					print(item.strip('"'))
				else:
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
		"""Methode de lecture variable"""
		output=''
		for key,value in dictio.items():
			output+='\n-----------------\n'
			#Display ReverseDNS
			if (type=='RD'):
				output+='IP : ' + key + '\n'
			else:
			#Display Brute-force subdomains
				output+='Sous-domaine : ' + key + '\n'
			output+='Resultat(s) : \n'
			if (isinstance(value, str)):
				output+=value+'\n'
			else:
				for item in value:
					output+=item+'\n'
			output+='-----------------\n'
		return output

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
		#print(liste)
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
					if (value in [200,403]):
						print(key + ' : ' + str(value))

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

	@decoratorTimerProcess
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
			print('Resultat du reverse DNS de classe C dans le fichier results/' + self.target.getUrl() + '_rev_dns.txt')
			output=self.lectureOtherResponse(self.target.getReverseDNS(), 'RD')
			self.writeResult('results/' + self.target.getUrl() + '_rev_dns.txt', output)
			#print(output)
		else:
			print('Reverse DNS ignore')

		choice=input('Voulez vous effectuer un brute-force des sous-domaines sur la cible ? (y/n) : ')
		resp=self.processResponseYN(choice)
		if (resp):
			print('Dictionnaire utilise : ' + self.dictio)
			print('Brute-force des sous-domaines en cours...')
			dnsenum.processBFSubDomain()
			print('Resultat du brute-force des sous domaines : ')
			output=self.lectureOtherResponse(self.target.getSubDomain(), 'BF')
			print(output)
		else:
			print('Brute-force des sous-domaines ignore')

	@decoratorTimerProcess
	def spiderSolo(self):
		"""Methode qui lance le Spider"""
		spider=Spider(self.target, self.dictio)
		print('Dictionnaire utilise : ' + self.dictio)
		print('Profondeur du spider : ' + str(self.depth))
		print('Brute-force de l\'arborescence en cours... ')
		spider.processDepthSpider(self.depth)
		self.lectureSpiderResponse(self.target.getArbo())

	def enumSpider(self):
		"""Methode qui lance l'enumeration DNS et le Spider"""
		#print('EnumSpider')
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
			if (self.args['-e']) and (self.args['-s']):
				self.enumSpider()
				self.quitCLI()
				continue
			if (self.args['-e']):
				self.enumSolo()
				self.quitCLI()
				continue
			if (self.args['-s']):
				self.spiderSolo()
				self.quitCLI()
				continue
			print('Que désirez-vous faire ?\n1 - Enumeration DNS\n2 - Spider\n3 - Enumeration DNS + Spider\n4 - Exit')
			choice=input('Votre choix ? : ')
			try:
				options[choice]()
			except KeyError as e:
				print(choice + ' : Choix inconnu')
