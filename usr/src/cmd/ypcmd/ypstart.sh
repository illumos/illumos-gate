#!/bin/sh
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Enable appropriate NIS daemons based on the current configuration.

enable () {
	/usr/sbin/svcadm enable -t $1
	[ $? = 0 ] || echo "ypstart: unable to enable $1"

	if [ "`/usr/bin/svcprop -p restarter/state $1`" = "maintenance" ]; then
		echo "ypstart: unable to enable $1; in maintenance"
	fi
}


domain=`domainname`
if [ -z "$domain" ]; then
	echo "ERROR: Default domain is not defined.  \c"
	echo "Use \"domainname\" to set the domain."
	exit 1
fi

echo "starting NIS (YP server) services:\c"

zone=`/sbin/zonename`

if [ -d /var/yp/$domain ]; then
	state=`/usr/bin/svcprop -p restarter/state network/nis/server:default`

	[ "$state" = "disabled" ] && if [ -n "`pgrep -z $zone ypserv`" ]; then
		echo "ypstart: ypserv already running?"
	fi

	enable svc:/network/nis/server:default && echo " ypserv\c"

	YP_SERVER=TRUE	# remember we're a server for later

	# check to see if we are the master
	if [ -f /var/yp/NISLDAPmapping ]; then
		passwdfile=/var/yp/$domain/LDAP_passwd.byname
	else
		passwdfile=/var/yp/$domain/passwd.byname
	fi
	master=`/usr/sbin/makedbm -u $passwdfile | grep YP_MASTER_NAME \
	    | nawk '{ print tolower($2) }'`
fi

# Enabling the YP client is not strictly necessary, but it is
# traditional.
state=`/usr/bin/svcprop -p restarter/state network/nis/client:default`

[ "$state" = "disabled" ] && if [ -n "`pgrep -z $zone ypbind`" ]; then
	echo "ypstart: ypbind already running?"
fi

enable svc:/network/nis/client:default && echo " ypbind\c"

# do a ypwhich to force ypbind to get bound
ypwhich > /dev/null 2>&1

if [ "$YP_SERVER" = TRUE ]; then
	# Are we the master server?  If so, start the
	# ypxfrd, rpc.yppasswdd and rpc.ypupdated daemons.
	hostname=`uname -n | tr '[A-Z]' '[a-z]'`

	if [ "$master" = "$hostname" ]; then
		enable svc:/network/nis/xfr:default && echo " ypxfrd\c"
		enable svc:/network/nis/passwd:default &&
		    echo " rpc.yppasswdd\c"

		if [ ! -f /var/yp/NISLDAPmapping -a -f /var/yp/updaters ]; then
			enable svc:/network/nis/update:default &&
			    echo " rpc.ypupdated\c"
		fi
	fi
fi

# As this operation is likely configuration changing, restart the
# name-services milestone (such that configuration-sensitive services
# are in turn restarted).
/usr/sbin/svcadm restart milestone/name-services

echo " done."
