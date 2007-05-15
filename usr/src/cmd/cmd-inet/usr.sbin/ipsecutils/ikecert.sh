#!/usr/bin/pfsh
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# ikecert is a wrapper to three programs in /usr/lib/inet which do the heavy
# lifting for IKE certificate database management (i.e. the files in
# /etc/inet/ike/publickeys, /etc/inet/secret/ike.privatekeys, and
# /etc/inet/ike/crls).
#

case "$1" in
'certdb')
	# Okay!  We're good to go.
	;;
'certrldb')
	# Okay!  We're good to go.
	;;
'certlocal')
	# Okay!  We're good to go.
	;;
'tokens')
	# Execute the special options of certlocal.
	exec /usr/lib/inet/certlocal -X
	;;

*)
	echo "Usage: ikecert { certdb | certrldb | certlocal | tokens }" \
		"<options> "
	echo "       Use '-h' after one of the cert-commands for more details."
	exit 1
	;;
esac

exec /usr/lib/inet/"$@"
