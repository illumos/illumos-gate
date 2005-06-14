#!/bin/sh
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
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

. /lib/svc/share/smf_include.sh

YPDIR=/usr/lib/netsvc/yp

case $SMF_FMRI in
	'svc:/network/nis/client:default')
		domain=`domainname`

		if [ -z "$domain" ]; then
			echo "$0: domainname not set"
			exit $SMF_EXIT_ERR_CONFIG
		fi

		if [ ! -d /var/yp/binding/$domain ]; then
			echo "$0: /var/yp/binding/$domain is not a directory"
			exit $SMF_EXIT_ERR_CONFIG
		fi

		# Since two ypbinds will cause ypwhich to hang...
		if pgrep -z `/sbin/zonename` ypbind >/dev/null; then
			echo "$0: ypbind is already running."
			exit $SMF_EXIT_ERR_CONFIG
		fi

		if [ -f /var/yp/binding/$domain/ypservers ]; then
			$YPDIR/ypbind > /dev/null 2>&1
		else
			$YPDIR/ypbind -broadcast > /dev/null 2>&1
		fi

		rc=$?
		if [ $rc != 0 ]; then
			echo "$0: ypbind failed with $rc"
			exit 1
		fi
		;;

	'svc:/network/nis/server:default')
		domain=`domainname`

		if [ -z "$domain" ]; then
			echo "$0: domainname not set"
			exit $SMF_EXIT_ERR_CONFIG
		fi

		if [ ! -d /var/yp/$domain ]; then
			echo "$0: domain directory missing"
			exit $SMF_EXIT_ERR_CONFIG
		fi

		if [ -f /etc/resolv.conf ]; then
			$YPDIR/ypserv -d
		else
			$YPDIR/ypserv
		fi

		rc=$?
		if [ $rc != 0 ]; then
			echo "$0: ypserv failed with $rc"
			exit 1
		fi
		;;

	'svc:/network/nis/passwd:default')
		PWDIR=`grep "^PWDIR" /var/yp/Makefile 2> /dev/null` \
		    && PWDIR=`expr "$PWDIR" : '.*=[ 	]*\([^ 	]*\)'`
		if [ "$PWDIR" ]; then
			if [ "$PWDIR" = "/etc" ]; then
				unset PWDIR
			else
				PWDIR="-D $PWDIR"
			fi
		fi
		$YPDIR/rpc.yppasswdd $PWDIR -m

		rc=$?
		if [ $rc != 0 ]; then
			echo "$0: rpc.yppasswdd failed with $rc"
			exit 1
		fi
		;;

	*)
		echo "$0: Unknown service \"$SMF_FMRI\"."
		exit $SMF_EXIT_ERR_CONFIG
		;;
esac
exit $SMF_EXIT_OK
