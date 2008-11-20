#! /usr/bin/python
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Various database lookup classes/methods, i.e.:
#     * monaco
#     * bugs.opensolaris.org (b.o.o.)
#     * opensolaris.org/cgi/arc.py (for ARC)
#

import re
import urllib
import urllib2
import htmllib
import os
from socket import socket, AF_INET, SOCK_STREAM

from onbld.Checks import onSWAN

class BugException(Exception):
	def __init__(self, data=''):
		self.data = data
		Exception.__init__(self, data)

	def __str__(self):
		return "Unknown error: %s" % self.data

class NonExistentBug(BugException):
	def __str__(self):
		return "Bug %s does not exist" % self.data

class BugDBException(Exception):
	def __init__(self, data=''):
		self.data = data
		Exception.__init__(self, data)

	def __str__(self):
		return "Unknown bug database: %s" % self.data

class BugDB(object):
	"""Lookup change requests.

	Object can be used on or off of SWAN, using either monaco or
	bugs.opensolaris.org as a database.

	Usage:
	bdb = BugDB()
	r = bdb.lookup("6455550")
	print r["6455550"]["synopsis"]
	r = bdb.lookup(["6455550", "6505625"])
	print r["6505625"]["synopsis"]
	"""

	def __init__(self, priority = ("bugster",), forceBoo = False):
		"""Create a BugDB object.

		Keyword argument:
		forceBoo: use b.o.o even from SWAN (default=False)
		priority: use bug databases in this order
		"""
		self.__validBugDB = ["bugster"]
		self.__onSWAN = not forceBoo and onSWAN()
		for database in priority:
			if database not in self.__validBugDB:
				raise BugDBException, database
		self.__priority = priority


	def __boobug(self, cr):
		cr = str(cr)
		url = "http://bugs.opensolaris.org/view_bug.do"
   		req = urllib2.Request(url, urllib.urlencode({"bug_id": cr}))
		results = {}
		try:
			data = urllib2.urlopen(req).readlines()
		except urllib2.HTTPError, e:
			if e.code != 404:
				print "ERROR: HTTP error at " + \
					req.get_full_url() + \
					" got error: " + str(e.code)
				raise e
			else:
				raise NonExistentBug
		except urllib2.URLError, e:
			print "ERROR: could not connect to " + \
				req.get_full_url() + \
				' got error: "' + e.reason[1] + '"'
			raise e
		htmlParser = htmllib.HTMLParser(None)
		metaHtmlRe = re.compile(r'^<meta name="([^"]+)" content="([^"]*)">$')
		for line in data:
			m = metaHtmlRe.search(line)
			if not m:
				continue
			val = urllib.unquote(m.group(2))
			htmlParser.save_bgn()
			htmlParser.feed(val)
			results[m.group(1)] = htmlParser.save_end()
		htmlParser.close()

		if "synopsis" not in results:
			raise NonExistentBug(cr)
					
		results["cr_number"] = cr
		results["sub_category"] = results.pop("subcategory")
		results["status"] = results.pop("state")
		results["date_submitted"] = results.pop("submit_date")
		
		return results


	def __monaco(self, crs):
		"""Return all info for requested change reports.

		Argument:
		crs: list of change request ids

		Returns:
		Dictionary, mapping CR=>dictionary, where the nested dictionary
		is a mapping of field=>value
		"""
		
		#
		# We request synopsis last, and split on only
		# the number of separators that we expect to
		# see such that a | in the synopsis doesn't
		# throw us out of whack.
		#
		monacoFields = [ "cr_number", "category", "sub_category",
			"area", "release", "build", "responsible_manager",
			"responsible_engineer", "priority", "status", "sub_status",
			"submitted_by", "date_submitted", "synopsis" ]
		cmd = []
		cmd.append("set What = cr." + ', cr.'.join(monacoFields))
		cmd.append("")
		cmd.append("set Which = cr.cr_number in (" + ','.join(crs) +")")
		cmd.append("")
		cmd.append("set FinalClauses = order by cr.cr_number")
		cmd.append("")
		cmd.append("doMeta genQuery cr")
		url = "http://hestia.sfbay.sun.com/cgi-bin/expert?format="
		url += "Pipe-delimited+text;Go=2;no_header=on;cmds="
		url += urllib.quote_plus("\n".join(cmd))
		results = {}
		try:
			data = urllib2.urlopen(url).readlines()
		except urllib2.HTTPError, e:
			print "ERROR: HTTP error at " + url + \
				" got error: " + str(e.code)
			raise e

		except urllib2.URLError, e:
			print "ERROR: could not connect to " + url + \
				' got error: "' + e.reason[1] + '"'
			raise e
		for line in data:
			line = line.rstrip('\n')
			values = line.split('|', len(monacoFields) - 1)
			v = 0
			cr = values[0]
			results[cr] = {}
			for field in monacoFields:
				results[cr][field] = values[v]
				v += 1
		return results

	def lookup(self, crs):
		"""Return all info for requested change reports.

		Argument:
		crs: one change request id (may be integer, string, or list),
	             or multiple change request ids (must be a list)

		Returns:
		Dictionary, mapping CR=>dictionary, where the nested dictionary
		is a mapping of field=>value
		"""
		results = {}
		if not isinstance(crs, list):
			crs = [str(crs)]
		for database in self.__priority:
			if database == "bugster":				
				if self.__onSWAN:
					results.update(self.__monaco(crs))
				# else we're off-swan and querying via boo, which we can
				# only do one bug at a time
				else:
					for cr in crs:
						cr = str(cr)
						try:
							results[cr] = self.__boobug(cr)
						except NonExistentBug:
							continue

			# the CR has already been found by one bug database
			# so don't bother looking it up in the others
			for cr in crs:
				if cr in results:
					crs.remove(cr)
		
		return results
####################################################################
def ARC(arclist):
	opts = {}
	url = "http://opensolaris.org/cgi/arc.py"
	opts["n"] = str(len(arclist))
	for i, arc in enumerate(arclist):
		arc, case = arc
		opts["arc" + str(i)] = arc
		opts["case" + str(i)] = case
	req = urllib2.Request(url, urllib.urlencode(opts))
	try:
		data = urllib2.urlopen(req).readlines()
	except urllib2.HTTPError, e:
		print "ERROR: HTTP error at " + req.get_full_url() + \
			" got error: " + str(e.code)
		raise e

	except urllib2.URLError, e:
		print "ERROR: could not connect to " + req.get_full_url() + \
			' got error: "' + e.reason[1] + '"'
		raise e
	ret = {}
	for line in data:
		oneline = line.rstrip('\n')
		fields = oneline.split('|')
		# check if each is valid ( fields[0]::validity )
		if fields[0] != "0":
			continue
		arc, case = fields[1].split(" ")
		ret[(arc, case)] = fields[2]
	return ret

####################################################################

# Pointers to the webrti server hostname & port to use
# Using it directly is probably not *officially* supported, so we'll
# have a pointer to the official `webrticli` command line interface
# if using a direct socket connection fails for some reason, so we
# have a fallback
WEBRTI_HOST = 'webrti.sfbay.sun.com'
WEBRTI_PORT = 9188
WEBRTICLI = '/net/onnv.sfbay.sun.com/export/onnv-gate/public/bin/webrticli'


class RtiException(Exception):
	def __init__(self, data=''):
		self.data = data
		Exception.__init__(self, data)

	def __str__(self):
		return "Unknown error: %s" % self.data

class RtiCallFailed(RtiException):
	def __str__(self):
		return "Unable to call webrti: %s" % self.data

class RtiSystemProblem(RtiException):
	def __str__(self):
		return "RTI status cannot be determined: %s" % self.data

class RtiIncorrectCR(RtiException):
	def __str__(self):
		return "Incorrect CR number specified: %s" % self.data

class RtiNotFound(RtiException):
	def __str__(self):
		return "RTI not found: %s" % self.data

class RtiNeedConsolidation(RtiException):
	def __str__(self):
		return "More than one consolidation has this CR: %s" % self.data

class RtiBadGate(RtiException):
	def __str__(self):
		return "Incorrect gate name specified: %s" % self.data

class RtiOffSwan(RtiException):
	def __str__(self):
		return "RTI status checks need SWAN access: %s" % self.data

WEBRTI_ERRORS = {
	'1': RtiSystemProblem,
	'2': RtiIncorrectCR,
	'3': RtiNotFound,
	'4': RtiNeedConsolidation,
	'5': RtiBadGate,
}

# Our Rti object which we'll use to represent an Rti query
# It's really just a wrapper around the Rti connection, and attempts
# to establish a direct socket connection and query the webrti server
# directly (thus avoiding a system/fork/exec call).  If it fails, it
# falls back to the webrticli command line client.

returnCodeRe = re.compile(r'.*RETURN_CODE=(\d+)')
class Rti:
	"""Lookup an RTI.

	Usage:
	r = Rti("6640538")
	print r.rtiNumber();
	"""

	def __init__(self, cr, gate=None, consolidation=None):
		"""Create an Rti object for the specified change request.

		Argument:
		cr: change request id

		Keyword arguments, to limit scope of RTI search:
		gate: path to gate workspace (default=None)
		consolidation: consolidation name (default=None)
		"""

		bufSz = 1024
		addr = (WEBRTI_HOST, WEBRTI_PORT)
		# If the passed 'cr' was given as an int, then wrap it
		# into a string to make our life easier
		if isinstance(cr, int):
			cr = str(cr)
		self.__queryCr = cr
		self.__queryGate = gate
		self.__queryConsolidation = consolidation

		self.__webRtiOutput = []
		self.__mainCR = []
		self.__rtiNumber = []
		self.__consolidation = []
		self.__project = []
		self.__status = []
		self.__rtiType = []
		try:
			# try to use a direct connection to the
			# webrti server first
			sock = socket(AF_INET, SOCK_STREAM)
			sock.connect(addr)
			command = "WEBRTICLI/1.0\nRTIstatus\n%s\n" % cr
			if consolidation:
				command += "-c\n%s\n" % consolidation
			if gate:
				command += "-g\n%s\n" % gate
			command += "\n"
			sock.send(command)
			dataList = []
			# keep receiving data from the socket until the
			# server closes the connection
			stillReceiving = True
			while stillReceiving:
				dataPiece = sock.recv(bufSz)
				if dataPiece:
					dataList.append(dataPiece)
				else:
					stillReceiving = False
			# create the lines, skipping the first
			# ("WEBRTCLI/1.0\n")
			data = '\n'.join(''.join(dataList).split('\n')[1:])
		except:
			if not onSWAN():
				raise RtiOffSwan(cr)

			if not os.path.exists(WEBRTICLI):
				raise RtiCallFailed('not found')

			# fallback to the "supported" webrticli interface
			command = WEBRTICLI
			if consolidation:
				command += " -c " + consolidation
			if gate:
				command += " -g " + gate
			command += " RTIstatus " + cr

			try:
				cliPipe = os.popen(command)
			except:
				# we couldn't call the webrticli for some
				# reason, so return a failure
				raise RtiCallFailed('unknown')

			data = cliPipe.readline()

		# parse the data to see if we got a return code
		# if we did, then that's bad.  if we didn't,
		# then our call was successfully
		m = returnCodeRe.search(data)
		if m:
			# we got a return code, set it in our
			# object, set the webRtiOutput for debugging
			# or logging, and return a failure
			if m.group(1) in WEBRTI_ERRORS:
				exc = WEBRTI_ERRORS[m.group(1)]
			else:
				exc = RtiException
			raise exc(data)

		data = data.splitlines()
		# At this point, we should have valid data
		for line in data:	
			line = line.rstrip('\r\n')
			self.__webRtiOutput.append(line) 
			fields = line.split(':')
			self.__mainCR.append(fields[0])
			self.__rtiNumber.append(fields[1])
			self.__consolidation.append(fields[2])
			self.__project.append(fields[3])
			self.__status.append(fields[4])
			self.__rtiType.append(fields[5])

	# accessors in case callers need the raw data
	def mainCR(self):
		return self.__mainCR
	def rtiNumber(self):
		return self.__rtiNumber
	def consolidation(self):
		return self.__consolidation
	def project(self):
		return self.__project
	def status(self):
		return self.__status
	def rtiType(self):
		return self.__rtiType
	def queryCr(self):
		return self.__queryCr
	def queryGate(self):
		return self.__queryGate
	def queryConsolidation(self):
		return self.__queryConsolidation

	# in practice, most callers only care about the following
	def accepted(self):
		for status in self.__status:
			if status != "S_ACCEPTED":
				return False
		return True

	# for logging/debugging in case the caller wants the raw webrti output
	def webRtiOutput(self):
		return self.__webRtiOutput

