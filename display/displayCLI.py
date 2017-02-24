#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from threading import Thread
from dom.domain import *

class displayCLI(Thread):
	"""Classe qui modelise l'affichage en console"""

	def __init__(self, dom):
		Thread.__init__(self)
		self.running = False
		#if (dom[:6] != 'http://'):
		#	dom='http://' + dom
		#if (dom[-1] != '/'):
		#	dom=dom + '/'
		self.target=Domain(dom)

	def lectureAttr(self, liste):
		if liste == []:
			print('Pas de réponse')
		else:
			if (isinstance(liste, str)):
				print(liste)
			else:
				print('Reponse : ')
				print(liste['ans'])
				print('Informations additionnelles : ')
				print(liste['add'])

	def displayDnsEnum(self):
		print('IP de la cible : ')
		self.lectureAttr(self.target.getIP())
		print('Nameserver de la cible : ')
		self.lectureAttr(self.target.getNS())

	def enumSolo(self):
		print('EnumSolo')
		dnsenum=Dnsenum(self.target, 'test.txt')
		print('Enumeration DNS en cours')
		dnsenum.processDig()
		print('Fait')
		self.displayDnsEnum()

	def spiderSolo(self):
		print('SpiderSolo')

	def enumSpider(self):
		print('EnumSpider')

	def quitCLI(self):
		print('Bye !')
		self.running = False

	def run(self):
		
		options={'1': self.enumSolo,
					'2': self.spiderSolo,
					'3': self.enumSpider,
					'4': self.quitCLI,
		}
		self.running = True
		print('Bienvenue !')
		while self.running:
			print('Que désirez-vous faire ?\n1 - Enumeration DNS\n2 - Spider\n3 - Enumeration DNS + Spider\n4 - Exit')
			choice=input('Votre choix ? : ')
			try:
				options[choice]()
			except KeyError as e:
				print(choice + ' : Choix inconnu')

