#!/usr/bin/python
# -*- coding: utf-8 -*-

#Set of classes that manage redirections and HTTP's errors

from urllib.request import HTTPRedirectHandler, HTTPDefaultErrorHandler, Request, HTTPError

class SmartRedirectHandler(HTTPRedirectHandler):
	"Class which manages HTTP's redirections"
     
	def http_error_301(self, req, fp, code, msg, headers):
		"Method which manages HTTP's codes HTTP 301 (Moved permanently)"  
		result = HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, headers)              
		result.status = code
		result.newurl = result.geturl()                                 
		return result                                       

	def http_error_302(self, req, fp, code, msg, headers):
		"Method which manages HTTP's codes HTTP 302 (Moved Temporarily)"   
		result = HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)              
		result.status = code
		result.newurl = result.geturl()                      
		return result
 
class DefaultErrorHandler(HTTPDefaultErrorHandler):
	"Class which manages HTTP's errors by default"

	def http_error_default(self, req, fp, code, msg, headers):
		"Method which manages HTTP's errors by default"
		result = HTTPError(req.get_full_url(), code, msg, headers, fp)       
		result.status = code
		return result
