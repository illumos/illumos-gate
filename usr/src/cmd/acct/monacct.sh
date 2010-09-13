#!/sbin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
#	"this procedure should be run periodically ( by month or fiscal )"
_adm=/var/adm
_sum=${_adm}/acct/sum
_fiscal=${_adm}/acct/fiscal
PATH=:/usr/lib/acct:/usr/bin:/usr/sbin
export PATH


#if test $# -ne 1; then
#	echo "usage: monacct fiscal-number"
#	exit
#fi

_period=${1-`date +%m`}

cd ${_adm}

#	"move summary tacct file to fiscal directory"
mv ${_sum}/tacct ${_fiscal}/tacct${_period}

#	"delete the daily tacct files"
rm -f ${_sum}/tacct????

#	"restart summary tacct file"
nulladm ${_sum}/tacct

#	"move summary cms file to fiscal directory
mv ${_sum}/cms ${_fiscal}/cms${_period}

#	"restart summary cms file"
nulladm ${_sum}/cms

#	"remove old prdaily reports"
rm -f ${_sum}/rprt*

#	"produce monthly reports"
prtacct ${_fiscal}/tacct${_period} > ${_fiscal}/fiscrpt${_period}
acctcms -a -s ${_fiscal}/cms${_period} |  \
pr -h "TOTAL COMMAND SUMMARY FOR FISCAL ${_period}" >> ${_fiscal}/fiscrpt${_period}
pr -h "LAST LOGIN" -3 ${_sum}/loginlog >> ${_fiscal}/fiscrpt${_period}

#	"add commands here to do any charging of fees, etc"
exit
