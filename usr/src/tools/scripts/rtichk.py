#!/usr/bin/python2.4
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

#
# Check each bug referenced in a comments list (from stdin) has a valid RTI
#

import sys, os, getopt

sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "lib",
                                "python%d.%d" % sys.version_info[:2]))

# Allow running from the source tree, using the modules in the source tree
sys.path.insert(2, os.path.join(os.path.dirname(__file__), '..'))

from onbld.Checks.Rti import rti


def usage():
    print 'usage: rtichk [-g gate] [-c consolidation] bugids...'
    sys.exit(2)

try:
	opts, bugs = getopt.getopt(sys.argv[1:], "c:g:r:t:")
except getopt.GetoptError:
	usage()
	sys.exit(2)

gate = None
consolidation = None

for opt, arg in opts:
	if opt == '-c': consolidation = arg
	elif opt == '-g': gate = arg

ret = not rti(bugs, consolidation=consolidation, gatePath=gate,
	      output=sys.stdout)
sys.exit(ret)
