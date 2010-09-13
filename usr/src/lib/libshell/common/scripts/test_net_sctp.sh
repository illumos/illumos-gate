#!/usr/bin/ksh93

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
# test_net_sctp - a simple ksh93 SCTP demo
#

export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

set -o xtrace
set -o errexit

# declare variables
integer netfd
typeset request

# print intro
print "# testing SCTP support"
print "# (via fetching the main page of http://www.sctp.org/ via SCTP)"

# open sctp stream and print it's number
redirect {netfd}<> /dev/sctp/www.sctp.org/80
print "sctp fd=${netfd}"

# send HTTP request    
request="GET / HTTP/1.1\r\n"
request+="Host: www.sctp.org\r\n"
request+="User-Agent: ksh93/test_net_sctp (2009-04-08; $(uname -s -r -p))\r\n"
request+="Connection: close\r\n"
print -u${netfd} -n -- "${request}\r\n"

# print response to stdout
cat <&${netfd}

# close connection
redirect {netfd}<&-

print "#done"

#EOF.
