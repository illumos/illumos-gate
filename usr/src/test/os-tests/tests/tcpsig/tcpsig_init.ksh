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

AUTHSTR="I want a biscuit, yes, twice cooked!"
ALTAUTHSTR="x$AUTHSTR"

for ip in 127.0.0.1 ::1; do
	/usr/sbin/tcpkey 2>&1 <<- EOM || exit 1
	# A matching pair
	add src $ip dst $ip dport 24135 authalg md5 authstring "$AUTHSTR"
	add src $ip dst $ip sport 24135 authalg md5 authstring "$AUTHSTR"
	# Mismatched keys
	add src $ip dst $ip dport 24136 authalg md5 authstring "$AUTHSTR"
	add src $ip dst $ip sport 24136 authalg md5 authstring "$ALTAUTHSTR"
	# Outbound entry only
	add src $ip dst $ip dport 24137 authalg md5 authstring "$AUTHSTR"
	# Inbound entry only
	add src $ip dst $ip sport 24138 authalg md5 authstring "$AUTHSTR"
	EOM
done

exit 0
