#!ON_PYTHON
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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

# Copyright 2010, Richard Lowe
# Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
# Copyright (c) 2019, Joyent, Inc.

#
# Various database lookup classes/methods, i.e.:
#     * redmine (illumos.org)
#     * smartos
#

import re
import json
try:
	from urllib.request import urlopen, Request
	from urllib.error import HTTPError
except ImportError:
	# Python 2
	from urllib2 import Request, urlopen, HTTPError

try:				# Python >= 2.5
	from xml.etree import ElementTree
except ImportError:
	from elementtree import ElementTree

class NonExistentBug(Exception):
	def __str__(self):
		return "Bug %s does not exist" % (Exception.__str__(self))

class BugDBException(Exception):
	def __str__(self):
		return "Unknown bug database: %s" % (Exception.__str__(self))

class BugDB(object):
	"""Lookup change requests.

	Usage:
	bdb = BugDB()
	r = bdb.lookup("6455550")
	print r["6455550"]["synopsis"]
	r = bdb.lookup(["6455550", "6505625"])
	print r["6505625"]["synopsis"]
	"""

	VALID_DBS = ["illumos", "smartos"]

	def __init__(self, priority = VALID_DBS):
		"""Create a BugDB object.

		Keyword argument:
		priority: use bug databases in this order
		"""
		for database in priority:
			if database not in self.VALID_DBS:
				raise BugDBException(database)
		self.__priority = priority

	def __smartosbug(self, cr):
		url = "http://smartos.org/bugview/json/%s" % cr
		req = Request(url)

		try:
			data = urlopen(req)
		except HTTPError, e:
			if e.code == 404 or e.code == 403 or e.code == 400:
				raise NonExistentBug(cr)
			else:
				raise

		bug = json.load(data)

		return {'cr_number': bug['id'],
			'synopsis': bug['summary']
		}


	def __illbug(self, cr):
		url = "http://illumos.org/issues/%s.xml" % cr
		req = Request(url)

		try:
			data = urlopen(req)
		except HTTPError as e:
			if e.code == 404:
				raise NonExistentBug(cr)
			else:
				raise

		bug = ElementTree.parse(data)

		return {'cr_number': bug.find('id').text,
			'synopsis': bug.find('subject').text,
			'status': bug.find('status').attrib['name']
		}


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
			if database == "illumos":
				for cr in crs:
					try:
						results[str(cr)] = self.__illbug(cr)
					except NonExistentBug:
						continue
			elif database == "smartos":
				for cr in crs:
					try:
						results[str(cr)] = self.__smartosbug(cr)
					except NonExistentBug:
						continue

			# the CR has already been found by one bug database
			# so don't bother looking it up in the others
			for cr in crs:
				if cr in results:
					crs.remove(cr)

		return results
