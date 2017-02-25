#!/usr/bin/python
# -*- coding: utf-8 -*-

import time
from urllib.request import Request, build_opener, URLError
from http.client import HTTPConnection
from lib import openanything

class Spider():
	"""Classe qui modelise le processus de decouverte de l arborescence"""
	
	#Methode init - Getter/Setter
	def __init__(self, domain, dictio='directories.jbrofuzz'):
		"""Initialisee avec un objet Domain et un dictionnaire"""
		self.dictio='dic/'+dictio
		self.domain=domain

	def getDictio(self):
		return self.dictio

	def setDictio(self, dictio):
		self.dictio=dictio

	def processDoublons(self, liste):
		"""Traitement des doublons dans les listes"""
		listeProcess=[]
		for i in liste:
			if i not in listeProcess:
				listeProcess.append(i)
		return listeProcess

	def codeFilter(self, dictResult, listeFiltered):
		"""Filtrage des codes HTTP qui nous interessent"""
		for cle,valeur in dictResult.items():
			if (valeur in [200, 403]):
				#On enleve les parametres d'Url eventuels
				indexF=cle.find('?')
				if (indexF != -1):
					#print('Param GET')
					dictResult[cle[:indexF]]=valeur
					del dictResult[cle]
				listeFiltered.append(dictResult)
		

	def processHttpError(self, opener, request, result, url):
		"""Traitement des erreurs d'URL mal formees et des codes 4** et 5**"""
		testDataStream=''
		try:
			testDataStream = opener.open(request)
		except URLError as e:
			#Si erreur, il y a un probleme avec l'URL, on sort de la méthode
			result[url]=str(e.reason)
			return result
		code=testDataStream.status
		if ((str(code))[0] == '4') or ((str(code))[0] == '5'):
			result[url]=code
			return result

	def requestBF(self, url):
		"""Methode qui modelise les requetes de brute-force de l arborescence"""

		result={}
		requestInit=Request(url)
		#print('Requete : ' + url)
		time.sleep(2)
		HTTPConnection.debuglevel = 0
		openerErr = build_opener(openanything.DefaultErrorHandler())
		self.processHttpError(openerErr, requestInit, result, url)
		if (result != {}):
			return result
		
		openerRed = build_opener(openanything.SmartRedirectHandler())
		f = openerRed.open(requestInit)
		result[url]=f.status
		if ((str(f.status))[0] == '3'):
			codeRedir=0
			while (codeRedir != 200):
				requestRedir=Request(f.newurl)
				#print('Requete de redirection : ' + f.newurl)
				self.processHttpError(openerErr, requestRedir, result, f.newurl)
				fRedir = openerRed.open(requestRedir)
				codeRedir=fRedir.status
				result[f.newurl]=fRedir.status
		return result

	def processSpider(self, listeFin):
		"""Methode qui brute-force l'arborescence de l'url de l objet Domain passe a la classe en utilisant le dictionnaire propriete de la classe"""
		
		#On verifie une eventuelle redirection de domaine sur la cible (souvent vers le sous-domaine www)
		listTree=[]

		#Si la liste finale est vide, c'est la premiére itération sur le domaine, on teste la redirection
		if (listeFin == []):
			#print('Test initial')
			dom=self.domain.url
			if (dom[:6] != 'http://'):
				dom='http://' + self.domain.url
			if (dom[-1] != '/'):
				dom=dom + '/'
			result=self.requestBF(dom)
			#print(result)
			for cle,valeur in result.items():
				#Si le code HTTP est 200 et que la liste result a plus d un element, c'est une redirection
				if (valeur == 200) and (len(result) > 1):
					#print('Redirection sur la cible.')
					self.domain.setUrl(cle)
					break

		with open(self.dictio, 'r') as f:
			for line in f:

				#Commentaire dans le dictionnaire
				if (line[0] == '#'):
					continue

				#Si la liste finale n'est pas vide, ce n'est pas la premiére itération sur le domaine,
				if (listeFin != []):
					for dictio in listeFin[-1]:
						for url,code in dictio.items():
							if (code in [200, 403]):
								url=url.strip('\n')
								#Avec les reecriture d'URL, on ne fait plus la difference entre fichier et dossier
								if (url[-1] != '/'):
									url=url+'/'
								#print('Requete depth : ' + url + line)
								result=self.requestBF(url+line)
								#print(result)
								self.codeFilter(result, listTree)
				else:
					#print(self.domain.url+line)
					result=self.requestBF(dom)
					#print('Test actuel : ' + line)
					#print(result)
				self.codeFilter(result, listTree)

		listTree=self.processDoublons(listTree)
		return listTree

	def processDepthSpider(self, depth):
		"""Methode qui execute le processus de spider selon une profondeur donnée"""
		listTriFinal=[]
		i=0
		while (i < depth):
			listTriFinal.append(self.processSpider(listTriFinal))
			i += 1
		return listTriFinal
