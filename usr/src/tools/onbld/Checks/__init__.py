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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# The 'checks' package contains various checks that may be run
#

__all__ = [
	'Cddl',
	'Comments',
	'Copyright',
	'CStyle',
	'HdrChk',
	'JStyle',
	'Keywords',
	'Mapfile',
	'Rti',
	'onSWAN']


import socket

# 
# Generic check to test if a host is on SWAN
# 
def onSWAN():
	try:
		if socket.gethostbyname("sunweb.central.sun.com."):
			return True
		else:
			return False
	except:
		return False
