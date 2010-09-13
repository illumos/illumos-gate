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

#
# Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.12	*/
#	"prdaily	prints daily report"
#	"last command executed in runacct"
#	"if given a date mmdd, will print that report"
PATH=/usr/lib/acct:/usr/bin:/usr/sbin

while getopts cl i
do
	case $i in
	c)	CMDEXCPT=1;;
	l)	LINEEXCPT=1;;
	?)	echo Usage: prdaily [-c] [-l] [mmdd] >&2
		exit 2;;
	esac
done
shift `expr $OPTIND - 1`
date=`date +%m%d`
_sysname="`uname -n`"
_nite=/var/adm/acct/nite
_lib=/usr/lib/acct
_sum=/var/adm/acct/sum

cd ${_nite}
if [ `expr "$1" : [01][0-9][0-3][0-9]` -eq 4 -a "$1" != "$date" ]; then
	if [ "$CMDEXCPT" = "1" ]
	then
		echo "Cannot print command exception reports except for `date '+%h %d'`" >&2
		exit 5
	fi
	if [ "$LINEEXCPT" = "1" ]
	then
		acctmerg -a < ${_sum}/tacct$1 | awk -f ${_lib}/ptelus.awk
		exit $?
	fi
	cat ${_sum}/rprt$1
	exit 0
fi

if [ "$CMDEXCPT" = 1 ]
then
	acctcms -a -s ${_sum}/daycms | awk -f ${_lib}/ptecms.awk
fi
if [ "$LINEEXCPT" = 1 ]
then
	acctmerg -a < ${_sum}/tacct${date} | awk -f ${_lib}/ptelus.awk
fi
if [ "$CMDEXCPT" = 1 -o "$LINEEXCPT" = 1 ]
then
	exit 0
fi
(cat reboots; echo ""; cat lineuse) | pr -h "DAILY REPORT FOR ${_sysname}"  

prtacct daytacct "DAILY USAGE REPORT FOR ${_sysname}"  
pr -h "DAILY COMMAND SUMMARY" daycms
pr -h "MONTHLY TOTAL COMMAND SUMMARY" cms 
pr -h "LAST LOGIN" -3 ../sum/loginlog  
exit 0
