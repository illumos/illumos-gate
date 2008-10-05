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
# Check on RTI status for bug IDs passed.
#
# How we obtain the bug IDs will vary per SCM.
# 	- For Teamware, we want to check the active list comments.
#	- For Mercurial, we can check the incoming changegroup (via the
#	  pretxnchangegroup hook) and abort if necessary
#
# This module is implemented as a generic checking module given a list of
# bug IDs.  It can then be wrapped or hooked into whatever SCM with an
# SCM-specific hook to parse and pass the requisite bug IDs
# 

import re, os, sys
from onbld.Checks.DbLookups import Rti, RtiException, RtiNotFound, RtiOffSwan

patchGateRe = re.compile(r'.*-patch.*')
testGateRe = re.compile(r'.*-(stc2|test)$')

def rti(bugids, gatePath=None, consolidation=None,
	output=sys.stderr):
	"""Return True iff each of the specified bugids has an approved RTI.

	Required argument:
	bugids:	list of seven-digit bug ids

	Keyword arguments, used to limit the scope of the RTI search:
	gatePath: fully qualified path to gate
	consolidation: name of the consolidation
	"""

	rtiType = "MarketingRelease"
	gateType = "MarketingRelease"

	# Check to see if we were given a gate to lookup with
	if gatePath != None:

		#
		# The gate name should be the last component of the gate path,
		# no matter how it's accessed.
		#
		# We make a special case for "closed," and check to see if it
		# appears to be the "usr/closed" portion of a nested repository.
		# In that case, we really want the parent repository name.
		#
		gatePath = gatePath.rstrip(os.path.sep).split(os.path.sep)
		gateName = gatePath[-1]
		try:
			if gatePath[-2:] == ['usr', 'closed']:
				gateName = gatePath[-3]
		except IndexError:
			pass

		# Is this a patch gate?
		if patchGateRe.search(gateName):
			rtiType = "Patch"
			gateType = "Patch"

		# Is this a test gate?
		if testGateRe.search(gateName):
			rtiType = "RTI"
			gateType = "RTI"
	else:
		gateName = None

	# Query RTI if there's a gate
	# Check the RTIs, caching them in the 'rtis' dictionary
	# We do our error checking/handling here
	rtis = {}
	badRtis = []
	for cr in bugids:
		# If we don't already have an Rti object for this cr cached,
		# then go create/query it
		if cr not in rtis.keys() + badRtis:
			try:
				rtis[cr] = Rti(cr, gateName, consolidation)
			except RtiOffSwan, e:
				output.write("%s\n" % e)
				return False
			except RtiNotFound, e:
				output.write("Error: no RTI found for bug %s\n"
					% cr)
				badRtis.append(cr)  
				continue
			except RtiException, e:
				output.write("%s\n" % e)
				badRtis.append(cr)
				continue

		crRti = rtis[cr]

		# If we've reached this point, then the Rti query succeeded,
		# and we didn't get an error back from webrti.  There is still
		# some sanity checking to be done, however
		rtiNumber = crRti.rtiNumber()
		rtiType = crRti.rtiType()
	
		# check to make sure the RTI type matches the gate type
		if not gateType in rtiType:
			message = "Error: for bug " + cr 
			for each in rtiNumber:
				message += " the RTI " +  each + "  is of " 
				message += rtiType[rtiNumber.index(each)] + " type "
			message += "but the parent gate " + gateName + " is a " 
			message += gateType + " gate.\n" + "A " + gateType
			message += " RTI must be submitted to putback bug " + cr + " to " 
			message += gateName  + ". \n"
			
			output.write( message )
			badRtis.append(cr)
			continue

		if not crRti.accepted():
			for each in rtiNumber:
				message = "Error: RTI " + each + " for CR " + cr + " is not in "
				message += "the accepted state.\n"
				output.write(message)
			badRtis.append(cr)
			continue
	
	if len(badRtis) > 0:
		return False

	return True

