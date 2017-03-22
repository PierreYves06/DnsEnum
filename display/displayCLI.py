#!/usr/bin/python
# -*- coding: utf-8 -*-

from math import *
import sys, time, os
from colorama import init, Fore, Back, Style
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

		#On parse les arguments fournis par l'utilisateur
		dom=args['DOMAIN']
		if (dom[:7] == 'http://'):
			dom=dom[7:]
		if (dom[:8] == 'https://'):
			dom=dom[8:]
		self.target=Domain(dom)
		if (args['-d']):
			self.dictio=args['-d']
		else:
			self.dictio=dictio
		if (args['--depth']):
			self.depth=int(args['--depth'])
		else:
			self.depth=depth
		if (args['-q']):
			self.verbose=False
		else:
			self.verbose=True
		self.args=args

	def writeResult(self, file, output):
		"""Methode d ecriture des resultats dans un fichier"""
		#Verification de l'existence du dossier de la cible
		if (os.path.exists('results/') == False):
			os.mkdir('results/')
		if (os.path.exists('results/' + self.target.getUrl()) == False):
			os.mkdir('results/' + self.target.getUrl())
		f=open('results/' + self.target.getUrl() + '/' + file, 'w')
		f.write(output)
		f.close()

	def decoratorTimerProcess(process):
		"""Decorateur ajoutant un timer a un process"""
		def timerProcess(self, name):
			start=time.time()
			process(self)
			interval=time.time() - start
			if interval < 60:
				print('\nTemps d execution ' + name + ' : ' + str(round(interval, 2)) + ' sec.')
			else:
				minutes=interval/60
				seconds=interval%60
				#print(interval)
				print('\nTemps d execution ' + name + ' : ' + str(floor(minutes)) + ' min et ' + str(floor(seconds)) + ' sec.')
		return timerProcess

	def verboseOnOff(self, output, file):
		"""Methode qui gere le mode verbeux"""
		if (self.verbose):
			print(output)
		self.writeResult(self.target.getUrl() + file, output)

	def parseListeDictio(self, liste):
		"""Methode de lecture de la liste de dictionnaire"""
		output=''
		if (isinstance(liste, str)):
			output+=liste.strip('"') + '\n'
		else:
			for item in liste:
				if (isinstance(item, str)):
					output+=item.strip('"') + '\n'
				else:
					for key,value in item.items():
						output+=key + ' : ' + value + '\n'
		return output

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
		output=''
		if liste == []:
			output+='Pas de réponse\n'
		else:
			if (isinstance(liste, str)):
				output+=liste + '\n'
			else:
				#output+='Reponse :\n'
				if (liste['ans'] == 'empty'):
					output+='Pas de réponse\n'
				else:
					output+=self.parseListeDictio(liste['ans'])

				output+='Informations additionnelles :\n'
				if (liste['add'] == 'empty'):
					output+='Pas d\'informations additionnelles\n'
				else:
					output+=self.parseListeDictio(liste['add'])
		return output

	def lectureSpiderResponse(self, liste):
		"""Methode de lecture des retours du Spider"""
		lvl=0
		output=''
		for item in liste:
			if (item == []):
				output+='Fin des resultats\n'
				break
			lvl+=1
			output+='Niveau de l\'arbo : ' + str(lvl) + '\n'
			for dictio in item:
				for key,value in dictio.items():
					if (value in [200,403]):
						output+=key + ' : ' + str(value) + '\n'
		return output

	def displayDnsEnum(self):
		"""Methode d'affichage de l'enumeration DNS"""
		output=''
		output+=Fore.CYAN + '\nIP de la cible :' + Style.RESET_ALL + '\n'
		output+=self.lectureDigResponse(self.target.getIP())
		output+=Fore.CYAN + '\nNameserver de la cible :' + Style.RESET_ALL + '\n'
		output+=self.lectureDigResponse(self.target.getNS())
		output+=Fore.CYAN + '\nServeur mail de la cible :' + Style.RESET_ALL + '\n'
		output+=self.lectureDigResponse(self.target.getMX())
		output+=Fore.CYAN + '\nEnregistrement TXT de la cible :' + Style.RESET_ALL + '\n'
		output+=self.lectureDigResponse(self.target.getTXT())
		return output

	@decoratorTimerProcess
	def enumSolo(self, name='Enumeration DNS'):
		"""Methode qui lance l'enumeration DNS"""
		dnsenum=Dnsenum(self.target, self.dictio)
		print('Enumeration DNS en cours...')
		dnsenum.processDig()
		print('Fait')
		output=self.displayDnsEnum()
		self.verboseOnOff(output, '_dnsenum.txt')
		print('Resultat de l\'enumeration DNS dans le fichier results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_dnsenum.txt')

		if (self.args['-f']):
			resp=True
		else:
			choice=input('Voulez vous effectuer un reverse DNS de classe C sur la cible ? (y/n) : ')
			resp=self.processResponseYN(choice)
		if (resp):
			print('Reverse DNS de classe C en cours...')
			dnsenum.processReverseDns()
			print('Fait')
			print('Resultat du reverse DNS de classe C dans le fichier results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_rev_dns.txt')
			output=self.lectureOtherResponse(self.target.getReverseDNS(), 'RD')
			self.writeResult(self.target.getUrl() + '_rev_dns.txt', output)
		else:
			print('Reverse DNS ignore')

		if (self.args['-f']):
			resp=True
		else:
			choice=input('Voulez vous effectuer un brute-force des sous-domaines sur la cible ? (y/n) : ')
			resp=self.processResponseYN(choice)
		if (resp):
			print('Dictionnaire utilise : ' + self.dictio)
			print('Brute-force des sous-domaines en cours...')
			dnsenum.processBFSubDomain()
			output=self.lectureOtherResponse(self.target.getSubDomain(), 'BF')
			self.verboseOnOff(output, '_bf_subdom.txt')
			print('Resultat du brute-force des sous-domaines dans le fichier results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_bf_subdom.txt')
		else:
			print('Brute-force des sous-domaines ignore')

	@decoratorTimerProcess
	def spiderSolo(self, name='Spider'):
		"""Methode qui lance le Spider"""
		spider=Spider(self.target, self.dictio)

		if (self.args['-f']):
			resp=True
		else:
			choice=input('Voulez vous parser un eventuel robots.txt ? (y/n) : ')
			resp=self.processResponseYN(choice)
		if (resp):
			print('Lecture du robots.txt...')
			output=spider.readRobotsTxt(self.target.getUrl())
			self.verboseOnOff(output, '_robots.txt')
			print('Robots.txt sauvegarde dans le fichier results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_robots.txt')
		else:
			print('Extraction du robots.txt ignore')

		print('Dictionnaire utilise : ' + self.dictio)
		print('Profondeur du spider : ' + str(self.depth))
		print('Brute-force de l\'arborescence en cours... ')
		spider.processDepthSpider(self.depth)
		output=self.lectureSpiderResponse(self.target.getArbo())
		self.verboseOnOff(output, '_spider.txt')
		print('Resultat du spider dans le fichier results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_spider.txt')

	def enumSpider(self):
		"""Methode qui lance l'enumeration DNS et le Spider"""
		self.enumSolo('Enumeration DNS')
		self.spiderSolo('Spider')

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
		#Colorama start
		init()
		print(Fore.CYAN + '\n\t\t\tPenTesting Scout v1.0' + Style.RESET_ALL + '\n')
		while self.running:
			print('Votre cible : ' + Fore.MAGENTA + self.target.getUrl() + Style.RESET_ALL + '\n')

			#Selon les arguments fournis, on lance la fonctionnalite voulue
			if (self.args['-e']) and (self.args['-s']):
				self.enumSpider()
				self.quitCLI()
				continue
			if (self.args['-e']):
				self.enumSolo('Enumeration DNS')
				self.quitCLI()
				continue
			if (self.args['-s']):
				self.spiderSolo('Spider')
				self.quitCLI()
				continue
			print('Que désirez-vous faire ?\n\n\t1 - '+ Fore.GREEN \
					+'Enumeration DNS' + Style.RESET_ALL + '\n\t2'\
					+ ' - '+ Fore.GREEN +'Spider' + Style.RESET_ALL\
					+ '\n\t3 - '+ Fore.GREEN +'Enumeration DNS + Spider'\
					+ Style.RESET_ALL + '\n\t4 - '+ Fore.GREEN +'Exit' + Style.RESET_ALL + '\n')
			choice=input('Votre choix ? : ')
			try:
				if (choice == '1'):
					options[choice]('Enumeration DNS')
				elif (choice == '2'):
					options[choice]('Spider')
				else:
					options[choice]()
			except KeyError as e:
				print(choice + ' : Choix inconnu')
