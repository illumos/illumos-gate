#!/usr/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2024 Oxide Computer Company
#

for ip in 127.0.0.1 ::1; do
	/usr/sbin/tcpkey >/dev/null 2>&1 <<- EOM
	delete src $ip dst $ip dport 24135
	delete src $ip dst $ip sport 24135
	delete src $ip dst $ip dport 24136
	delete src $ip dst $ip sport 24136
	delete src $ip dst $ip dport 24137
	delete src $ip dst $ip dport 24138
	delete src $ip dst $ip sport 24138
	EOM
done

exit 0
