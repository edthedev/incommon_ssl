#!/usr/bin/python
"""Comodo SSL Certificate API wrapper class
"""
__author__ = "Edward Delaporte <delaport@illinois.edu>, University of Illinois"
__copyright__ = "Copyright (C) 2011-2013 University of Illinois Board of Trustees. All rights reserved."
__license__ = "University of Illinois/NCSA Open Source License"

import suds

class CertificateServiceError(Exception):
	pass

class RequestFailedError(CertificateServiceError):
	pass

class NotReadyError(CertificateServiceError):
	pass

def getComodoService(settings):
	"""Return a ComodoService instance.
	@param settings - a ConfigParser instance containing the following keys:
	[comodo]
	org_id=...
	api_key=...
	user=...
	password=...
	login_uri=...
	"""
	org_id = settings.get('comodo', 'org_id')
	api_key = settings.get('comodo', 'api_key')
	user = settings.get('comodo', 'user')
	password = settings.get('comodo', 'password')
	login_uri = settings.get('comodo', 'login_uri')
	revoke_phrase = settings.get('comodo', 'revoke_phrase')

	service = ComodoSSLService(
		org_id = org_id,
		api_secret_key = api_key,
		user = user,
		password = password,
		login_URI = login_uri,
		revoke_phrase = revoke_phrase,
		)
	return service

SERVER_APACHE = 2
SERVER_IIS		= 14

# Notice the extra spaces...stay classy Comodo
AVAILABLE_CERTIFICATE_TYPES = [
   "InCommon SSL",
   "InCommon Intranet SSL",
   "InCommon Wildcard SSL Certificate ",
   "InCommon Multi Domain SSL ",
   "InCommon Unified Communications Certificate",
   "Comodo EV SGC SSL ",
   "Comodo EV Multi Domain SSL",
]

["InCommon SSL"]
WEB_SSL_CERT = "InCommon SSL"

class ComodoSMIMEService(object):
	"""Placeholder --- Not implemented service consumer for the Comodo SMIME certifcate API."""
	def __init__(self, org_id, api_secret_key, user, password, login_URI, revoke_phrase):
		self.WSDL = "https://cert-manager.com/ws/EPKIManager?wsdl"
		
		pass
	def request(self, csr, name, email):
		pass
		#result = self.SOAP.enroll(
		#	data['authData'],
		#	data['orgId'],
		#	data['secretKey'],
		#	data['username'], 
		#	data['email'], 
		#	data['csr'],
		#		)

class ComodoSSLService(object):

	def __init__(self, org_id, api_secret_key, user, password, 
            revoke_phrase, login_URI='InCommon'):
		"""
		@org_id Comodo customer ID
				Can be obtained from Admin UI in the
				 'Organization properties' - 'Client Cert' tab.
		@api_secret_key Secret Key for SSL
				Setting in Client Admin UI in 
				'Organization properties' - 'SSL Certificates' tab.
		@user - Comodo username, must have 'Client Cert' role within CCM account.
		@password - Password for the username
        @revoke_phrase - A certificate revocation passphrase. Cannot be left blank!
		@login_URI - Per Comodo API documentation: "URI for logging into account within CCM."
		"""
		# Organization identifier. Can be obtained from Admin UI
		#  - Organization properties - Client Cert tab.
		self.OrgID = org_id 

		# Secret Key
		# Setting in Client Admin UI
		# Organization Properties - SSL Certificates
		self.SecretKey = api_secret_key

		self.WSDL = "https://cert-manager.com/ws/EPKIManagerSSL?wsdl"
		
		self.Client = suds.client.Client(self.WSDL)

		self.RevokePhrase = revoke_phrase

		# self.Client.setLogin(user)
		self.SOAP = self.Client.service
		self.Factory = self.Client.factory
		self.Auth = self.Factory.create('authData')
		# self.Auth.customerLoginUri = "https://cert-manager.com/"
		self.Auth.customerLoginUri = login_URI 
		self.Auth.login = user
		self.Auth.password = password
		self.Debug = False

	def getServerType(self, server_type_name):
        '''A bit of a hack to convert server type names into API keys.'''
		comodoServerTypes = {'AOL':1,
		'Apache/ModSSL':2,
		'Apache-ModSSL':2,
		'Apache-SSL (Ben-SSL, not Stronghold)':3,
		'C2Net Stronghold':3,
		'Cisco 3000 Series VPN Concentrator':33,
		'Citrix':34,
'Cobalt Raq':5,
'Covalent Server Software':6,
'IBM HTTP Server':7,
'IBM Internet Connection Server':8,
'iPlanet':9,
'Java Web Server (Javasoft / Sun)':10,
'Lotus Domino':11,
'Lotus Domino Go!':12,
'Microsoft IIS 1.x to 4.x':13,
'Microsoft IIS 5.x and later':14,
'Netscape Enterprise Server':15,
'Netscape FastTrac':16,
'Novell Web Server':17,
'Oracle':18,
'Quid Pro Quo':19,
'R3 SSL Server':20,
'Raven SSL':21,
'RedHat Linux':22,
'SAP Web Application Server':23,
'Tomcat':24,
'Website Professional':25,
'WebStar 4.x and later':26,
'WebTen (from Tenon)':27,
'Zeus Web Server':28,
'Ensim':29,
'Plesk':30,
'WHM/cPanel':31,
'H-Sphere':32,
'OTHER':-1,
		}
		if comodoServerTypes.has_key(server_type_name):
			return comodoServerTypes[server_type_name]
		else:
			return None

	def request(self, csr, fqdns=[], years=1, server_type='Apache-ModSSL', cert_type='InCommon SSL'):
		"""Request a new SSL certificate from Comodo.

		@csr Certificate Signing Request
		@fqdns fully qualified domain names
		@serverType SERVER_APACHE or SERVER_IIS 

		@return Comodo Certificate ID

		"""
		# serverType = 2 # Apache/ModSSL
	
		serverType = self.getServerType(server_type)

		certTypes = self.getCertTypes()
		certType = None
		# print "Available certificate types: %s" % str(certTypes)
		for ct in certTypes:
			if ct.name.strip() == cert_type.strip():
				certType = ct
		if certType == None:
			raise Exception("A Comodo API error occurred. Requested certificate type %s is not available." % cert_type)

		# print dir(certType)

		data = {
				'authData': self.Auth, 
				'orgId': int(self.OrgID), 
				'secretKey': self.SecretKey,
				'csr': csr, 
				'phrase': self.RevokePhrase,
				'subjAltNames': ','.join(fqdns),
				'certType': certType, 
				'numberServers': 1,
				'serverType' 	 	: serverType,
				'term' 					: years,
				'comments':"",
			}
		
		# print "Data passed to Enroll: %s" % str(data)

		result = self.SOAP.enroll(
			data['authData'],
			data['orgId'],
			data['secretKey'],
			data['csr'],
			data['phrase'],
			data['subjAltNames'],
			data['certType'], 
			data['numberServers'],
			data['serverType'],
			data['term'], 
			data['comments'],
		)
		
		if result < 0:
			self.raiseError(result)
		else:
			return result

	def getCertTypes(self):
		"""Returns the certificate types available to the current user."""
		response = self.SOAP.getCustomerCertTypes(self.Auth)
		result = response.statusCode
		if result != 0:
			self.raiseError(result)
		return response.types

	def renew(self, certId):
		"""Request renewal of an SSL certificate previously issued from Comodo.
		@certId Comodo CCM certificate id
		@return True if the renewal was successfully submitted.
		"""
		result = self.SOAP.renew(certId)
		# result = response.statusCode
		if result == 0:
			return True
		if result == -4:
			raise ValueError("Invalid Comodo Certificate ID: %s" % certId)
			return False
		if result == -3:
			raise RequestFailedError("Comodo API error. The Comodo service may be down.")
			return False
		else:
			raiseError(result)
			return False

	def collect(self, certId):
		"""Collect the SSL certificate from Comodo.
		@certId Comodo CCM certificate id
		"""
		# if not self.certReady(certId):
		#	raise NotReadyError("The requested certificate has not been processed yet.") 
		
		response = self.SOAP.collect(
			self.Auth,
			certId,
			formatType = 1
			)
		# print "Debug: API.Collect Response: %s" % str(response)
		result = response.statusCode
		if result < 0: self.raiseError(result)
		if result == 0: return (None, None)
		ssl = response.SSL
		# print "Debug: API.Collect SSL object: %s" % str(ssl)
		cert = ssl['certificate']
		order_id = ssl['renewID']
		return (order_id, cert)

	def collectRenewed(self, renewId):
		response = self.SOAP.collect(
			renewId,
			formatType = 1
			)
		result = response.statusCode
		if result < 0: self.raiseError(result)
		ssl = response.SSL
		cert = ssl['certificate']
		order_id = ssl['renewID']
		return (order_id, cert)

	def certReady(self, certId):
		"""Return True if the requested SSL certificate is finished processing and available from Comodo.
		@certId Comodo CCM certificate id
		"""
		result = self.SOAP.getCollectStatus(self.Auth, certId)
		if result == 1:
			return True
		if result == 0:
			return False
		else:
			self.raiseError(result)

	def raiseError(self, result):
		if result < 0 and result > -7:
			raise RequestFailedError("The request could not be processed. (%d)" % result)
		if result == -14:
			raise RequestFailedError("Comodo API error. The Comodo service may be down. (%d)" % result)
		if result == -16 or result == -120:
			raise ValueError("Insufficient privileges.(%d)" % result)
		if result == -20:
			raise RequestFailedError("The certificate request has been rejected.(%d)" % result)
		if result == -21:
			raise RequestFailedError("The certificate has been revoked.(%d)" % result)
		if result == -22:
			raise RequestFailedError("Payment error.(%d)" % result)
		if result == -34:
			raise RequestFailedError("The secret key is invalid.(%d)" % result)
		if result == -40:
			raise RequestFailedError("Invalid Certiticate ID (Order IDs are not Certificate IDs). Certificate IDs are normally 5 characters long and only returned by the API.(%d)" % result)
		if result == -100:
			raise ValueError("Invalid login or password.(%d)" % result)
		if result == -101:
			raise ValueError("Invalid organization credentials.(%d)" % result)
		if result == -110 or result == -111:
			raise ValueError("Illegal domain requested.(%d)" % result)
		raise ValueError("An unknown error occurred. See Comodo API documents for error number %s." % result)

