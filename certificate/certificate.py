#!/usr/bin/python

'''Functions for converting SSL certificates between formats.'''

__author__ = "Edward Delaporte, Lead Software Developer, University of Illinois, Keith Schoenefeld, Security Officer, University of Illinois"
__copyright__ = "Copyright (C) 2010-2013 University of Illinois Board of Trustees. All rights reserved."
__python_version__ = '2.5'

import subprocess, shlex
import tempfile
from OpenSSL import crypto

def findCertificateInText(text):
	"""Returns just the certificate text from a block of text containing a certificate."""
	signedCert = ''
	readCert = False
	for res in text.splitlines(True):
		if (readCert == True or res == '-----BEGIN CERTIFICATE-----\n') and res <> '-----END CERTIFICATE-----\n':
			readCert = True
			signedCert += res
		elif res == '-----END CERTIFICATE-----\n':
			readCert = False
			signedCert += res
	return res

def convertToPKCS7(x509CertText, CertAuthorityPath):
	"""Convert an X509 certificate into a PKCS7 certificate."""
	x509File  = tempfile.NamedTemporaryFile(delete=True)
	x509File.write(x509CertText)
	command = "openssl crl2pkcs7 -nocrl -certfile %s -certfile %s" % (x509File.name, CertAuthorityPath)
	commandArgs = shlex.split(command)
	p = subprocess.Popen(commandArgs, stdout=subprocess.PIPE)
	results = p.stdout.read()
	x509File.close()
	return results

def ValidateCSR(csr):
	"""Check the CSR for appropriate University of Illinois values. 
	   Return a collection of all errors found. A valid csr will have len(errors) == 0."""
	errors = []
	valid = []
	if csr is None:
		errors.append("No CSR found.")
		return errors 
	   
	if csr is "": 
		errors.append("CSR is an empty string.")
		return errors

	request = crypto.load_certificate_request( crypto.FILETYPE_PEM, csr )
	subject = request.get_subject()
	pubkey = request.get_pubkey()
	
		# Apparently there is no such property.
		#if req.is_valid():
		#	self.valid.append("The CSR is a CSR.")
		#else:
		#	self.errors.append("The CSR is not a CSR.")

	# Country: US
	if subject.countryName == "US":
		valid.append("Country Name is valid: US")
	else:
		errors.append("Country Name is invalid: Set to 'US'")

	# State: Illinois
	if subject.stateOrProvinceName == "Illinois":
		valid.append("State is valid: Illinois")
	else:
		errors.append("State is invalid: Set to 'Illinois'")
	# Location: Urbana
	if subject.localityName == "Urbana":
		valid.append("Locality is valid: Urbana")
	else:
		errors.append("Locality is invalid: Set to 'Urbana'")

	# Bits: >= 2048

