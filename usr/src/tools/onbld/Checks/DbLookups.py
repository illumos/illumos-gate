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
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Various database lookup classes/methods, i.e.:
#     * monaco
#     * bugs.opensolaris.org (b.o.o.)
#     * opensolaris.org/cgi/arc.py (for ARC)
#

import re
import urllib
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

class Monaco(object):
	"""
	Query bug database.

	Methods:
	queryBugs()
	expertQuery()
	"""
	
	def __init__(self):
		self.__baseURL = "http://hestia.sfbay.sun.com/cgi-bin/expert?"

	def expertQuery(self, cmd, format="Normal+text", header=False):
		"""Return results of user-supplied bug query.

		Argument:
		cmd: query to run

		Keyword arguments:
		format: desired output format (default="Normal+text")
		header: include headers in output? (default=False)

		Returns:
		List of lines representing the output from Monaco
		"""

		url = self.__baseURL + "format=" + format + ";Go=2;"
		if not header: url += "no_header=on;"
		url += "cmds=" + urllib.quote_plus("\n".join(cmd))
		myMonaco = urllib.urlopen(url)
		return myMonaco.readlines()

	def queryBugs(self, crs):
		"""Return all info for requested change reports.

		Argument:
		crs: list of change request ids

		Returns:
		Dictionary, mapping CR=>dictionary, where the nested dictionary
		is a mapping of field=>value
		"""
		monacoFields = [ "cr_number", "synopsis", "category", "sub_category",
			"area", "release", "build", "responsible_manager",
			"responsible_engineer", "priority", "status", "sub_status",
			"submitted_by", "date_submitted" ]
		cmd = []
		cmd.append("set What = cr." + ', cr.'.join(monacoFields))
		cmd.append("")
		cmd.append("set Which = cr.cr_number in (" + ','.join(crs) +")")
		cmd.append("")
		cmd.append("set FinalClauses = order by cr.cr_number")
		cmd.append("")
		cmd.append("doMeta genQuery cr")
		output = self.expertQuery(cmd, "Pipe-delimited+text")
		results = {}
		for line in output:
			values = line.split('|')
			v = 0
			cr = values[0]
			results[cr] = {}
			for field in monacoFields:
				results[cr][field] = values[v]
				v += 1
		return results

class BooBug(object):
	"""Look up a single bug on bugs.opensolaris.org."""
	def __init__(self, cr):
		cr = str(cr)
		url = "http://bugs.opensolaris.org/view_bug.do?bug_id="+cr
		data = urllib.urlopen(url).readlines()
		self.__fields = {}
		self.__fields["cr_number"] = cr
		htmlParser = htmllib.HTMLParser(None)
		metaHtmlRe = re.compile(r'^<meta name="([^"]+)" content="([^"]*)">$')
		for line in data:
			m = metaHtmlRe.search(line)
			if not m:
				continue
			val = urllib.unquote(m.group(2))
			htmlParser.save_bgn()
			htmlParser.feed(val)
			self.__fields[m.group(1)] = htmlParser.save_end()
		htmlParser.close()
		if "synopsis" not in self.__fields:
			raise NonExistentBug(cr)
	
	def synopsis(self):
		return self.__fields["synopsis"]
	def product(self):
		return self.__fields["product"]
	def cat(self):
		return self.__fields["category"]
	def subcat(self):
		return self.__fields["subcategory"]
	def keywords(self):
		return self.__fields["keywords"]
	def state(self):
		return self.__fields["state"]
	def submit_date(self):
		return self.__fields["submit_date"]
	def type(self):
		return self.__fields["type"]
	def date(self):
		return self.__fields["date"]
	def number(self):
		return self.__fields["cr_number"]

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

	def __init__(self, forceBoo = False):
		"""Create a BugDB object.

		Keyword argument:
		forceBoo: use b.o.o even from SWAN (default=False)
		"""
		if forceBoo:
			self.__onSWAN = False
		else:
			self.__onSWAN = onSWAN()
			if self.__onSWAN:
				self.__m = Monaco()

	def lookup(self, crs):
		"""Return all info for requested change reports.

		Argument:
		crs: one change request id (may be integer, string, or list),
	             or multiple change request ids (must be a list)

		Returns:
		Dictionary, mapping CR=>dictionary, where the nested dictionary
		is a mapping of field=>value
		"""
		if not isinstance(crs, list):
			crs = [str(crs)]
		if self.__onSWAN:
			results = self.__m.queryBugs(crs)
			return self.__m.queryBugs(crs)
		# else we're off-swan and querying via boo, which we can
		# only do one bug at a time
		results = {}
		for cr in crs:
			cr = str(cr)
			try:
				b = BooBug(cr)
			except NonExistentBug:
				continue
			
			results[cr] = {}
			results[cr]["cr_number"] = cr
			results[cr]["product"] = b.product()
			results[cr]["synopsis"] = b.synopsis()
			results[cr]["category"] = b.cat()
			results[cr]["sub_category"] = b.subcat()
			results[cr]["keywords"] = b.keywords()
			results[cr]["status"] = b.state()
			results[cr]["date_submitted"] = b.submit_date()
			results[cr]["type"] = b.type()
			results[cr]["date"] = b.date()

		return results

####################################################################

class ARC(object):
	"""Lookup an ARC case on opensolaris.org.

	Usage:
	a = ARC("PSARC", "2008/002")
	if a.valid():
		print a.name()
	"""
	def __init__(self, arc, case):
		self.__valid = False
		q = "http://opensolaris.org/cgi/arc.py?n=1"
		q += "&arc0=" + arc
		q += "&case0=" + case
		data = urllib.urlopen(q).readlines()
		self.__fields = {}
		for line in data:
			line = line.rstrip('\n')
			fields = line.split('|')
			validity = fields[0]

			if validity != "0":
				return
			else:
				self.__fields["Name"] = fields[2]

		self.__valid = True

	def valid(self):
		return self.__valid
	def name(self):
		return self.__fields["Name"]
	def status(self):
		return self.__fields["Status"]
	def type(self):
		return self.__fields["Type"]

####################################################################

# Pointers to the webrti server hostname & port to use
# Using it directly is probably not *officially* supported, so we'll
# have a pointer to the official `webrticli` command line interface
# if using a direct socket connection fails for some reason, so we
# have a fallback
WEBRTI_HOST = 'webrti.sfbay.sun.com'
WEBRTI_PORT = 9188
WEBRTICLI = '/net/webrti.sfbay.sun.com/export/home/bin/webrticli'


class RtiException(Exception):
	def __init__(self, data=''):
		self.data = data
		Exception.__init__(self, data)

	def __str__(self):
		return "Unknown error: %s" % self.data

# RtiInvalidOutput & RtiCallFailed are our "own" failures
# The other exceptions are triggered from WebRTI itself
class RtiInvalidOutput(RtiException):
	def __str__(self):
		return "Invalid output from WebRTI: %s" % self.data

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

		if data.count('\n') != 1:
			# there shouldn't be more than one line in
			# the output.  if we got more than one line,
			# then let's be paranoid, and abort.
			raise RtiInvalidOutput(data)

		# At this point, we should have valid data
		data = data.rstrip('\r\n')
		self.__webRtiOutput = data
		self.__fields = data.split(':')
		self.__mainCR = self.__fields[0]
		self.__rtiNumber = self.__fields[1]
		self.__consolidation = self.__fields[2]
		self.__project = self.__fields[3]
		self.__status = self.__fields[4]
		self.__rtiType = self.__fields[5]

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
		return (self.__status == "S_ACCEPTED")

	# for logging/debugging in case the caller wants the raw webrti output
	def webRtiOutput(self):
		return self.__webRtiOutput


