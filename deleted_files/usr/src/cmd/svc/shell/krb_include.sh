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

#ident	"%Z%%M%	%I%	%E% SMI"

BINDIR=/usr/lib/krb5
KDC_CONF_DIR=/etc/krb5

# default kadm5.acl file path
KADM5ACL=/etc/krb5/kadm5.acl

# krb5kdc's default db path
PRINCIPALDB=/var/krb5/principal

# syslog facility.level
OKFACLEV=daemon.notice
ERRFACLEV=daemon.crit

if [ ! -d $BINDIR ]; then	# /usr not mounted
	exit 1
fi

#return success (0) if an acl_file that is specified in the kdc.conf
#(or if not specified, the default one), is configured ("_default_realm_"
#replaced with the local realm name) else return failure (1).
kadm5_acl_configed() {

	#check acl_file relation values in the kdc.conf
	ACLFILES=`awk -F= '/^[ 	]*acl_file/ \
		    { printf("%s", $2) }' $KDC_CONF_DIR/kdc.conf`

	if [ -z "$ACLFILES" ]; then
		ACLFILES=$KADM5ACL
	fi

	for FILE in $ACLFILES; do
		if [ -s $FILE ]; then
			egrep -v '^[ 	]*#' $FILE | \
				egrep '_default_realm_' > /dev/null 2>&1
			if [ $? -gt 0 ]; then
				return 0
			fi
		fi
	done

	return 1
}

#return success (0) if a db exists in a path specified in kdc.conf or
#if none are specified in the kdc.conf, check the default path else
#return failure (1).
db_exists() {

	#check db names specified in the kdc.conf
	DBNAMES=`awk -F= '/^[ 	]*database_name/ \
		    { printf("%s", $2) }' $KDC_CONF_DIR/kdc.conf`

	if [ -z "$DBNAMES" ]; then
		#check default db path
		DBNAMES=$PRINCIPALDB
	fi

	for DB in $DBNAMES; do
		if [ -s $DB ]; then
			return 0
		elif [ -s ${DB}.db ]; then
			#db suffix no longer needed
			if mv ${DB}.db $DB; then
				logger -p $OKFACLEV \
				    "$0; renamed ${DB}.db to $DB"
				return 0
			else
				logger -p $ERRFACLEV \
				"$0: rename of ${DB}.db to $DB FAILED"
				return 1
			fi
		fi
	done

	return 1
}
