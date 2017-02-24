#!/usr/bin/python
# -*- coding: utf-8 -*-

#Ensemble de classes qui permettent de gerer les redirections et les erreurs HTTP
#A ameliorer en ajoutant des classes pour chaque types d erreurs (400 et 500)

from urllib.request import HTTPRedirectHandler, HTTPDefaultErrorHandler, Request, HTTPError

class SmartRedirectHandler(HTTPRedirectHandler):
	"Classe de gestion des redirections HTTP"
     
	def http_error_301(self, req, fp, code, msg, headers):
		"Methode de gestion des codes HTTP 301 (Redirection permanente)"  
		result = HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, headers)              
		result.status = code
		result.newurl = result.geturl()                                 
		return result                                       

	def http_error_302(self, req, fp, code, msg, headers):
		"Methode de gestion des codes HTTP 302 (Redirection temporaire)"   
		result = HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)              
		result.status = code
		result.newurl = result.geturl()                      
		return result
 
class DefaultErrorHandler(HTTPDefaultErrorHandler):
	"Classe des gestions des erreurs HTTP par defaut"

	def http_error_default(self, req, fp, code, msg, headers):
		"Methode de gestion des erreurs HTTP par defaut"
		result = HTTPError(req.get_full_url(), code, msg, headers, fp)       
		result.status = code
		return result
