#!/bin/sh --
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

# Check hostname configuration as per the sendmail code.
#
# See http://www.sendmail.org/sun-specific/migration.html#FQHN for details.
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PATH=/bin:/usr/sbin

# If $1 has a ".", accept it and exit.

accept_if_fully_qualified() {
	case $1 in
	*.*)
		echo "Hostname $myhostname OK: fully qualified as $1"
		exit 0
		;;
	esac
}

# Check the `getent hosts $1` output, skipping the 1st entry (IP address).

check_gethostbyname() {
	for host in `getent hosts $1 | awk '{for (f=2; f <= NF; f++) print $f}'`
	do
		accept_if_fully_qualified $host
	done
}

# Parse /etc/hosts, looking for $1 as an entry by itself, and try to find
# a long name on the same line.  First kill all comments, then check for
# $1 as a word by itself, then take just the first such line, then skip
# its first entry (IP address).

check_hosts_file() {
	for entry in `sed -e 's/#.*$//' /etc/hosts | \
		awk '/[ 	]'$1'([ 	]|$)/ \
			{for (f=2; f <= NF; f++) print $f; exit}'`
	do
		accept_if_fully_qualified $entry
	done
}

# Parse the output of `nslookup $1`, checking the Name and Aliases.

check_dns() {
	for host in `nslookup $1 2>/dev/null | \
		awk '$1 == "Name:" || $1 == "Aliases:"{print $2}'`
	do
		accept_if_fully_qualified $host
	done
}

# Check the `ypmatch $1 hosts` output, skipping the 1st entry (IP address).

check_nis() {
	for hst in `ypmatch $1 hosts | awk '{for (f=2; f <= NF; f++) print $f}'`
	do
		accept_if_fully_qualified $hst
	done
}

# Recommend how to reconfigure to get $1.$2 as the FQHN.
# $3 is the first entry for hosts in /etc/nsswitch.conf . 

suggest_fix_and_exit() {
	myhost=$1
	suggested_domain=$2
	fhe=$3
	myipaddr=`getent hosts $myhost | head -1 | awk '{print $1}'`

	# aliases: skip the 1st & 2nd entries: IP address & canonical name

	set -- '' '' '[ aliases ... ]'
	set -- `grep "^$myipaddr[	 ]" /etc/hosts 2>/dev/null`
	result=$?
	shift 2
	echo "We recommend \c"
	if [ "x$fhe" != "xfiles" ] ; then
		echo "listing files first for hosts in /etc/nsswitch.conf"
		echo "and then \c"
	fi
	if [ $result = 0 ] ; then
		echo "changing the /etc/hosts entry:\n"
		echo "$myipaddr $myhost $*\n"
		echo "to:\n"
	else
		echo "adding the /etc/hosts entry:\n"
	fi
	echo "$myipaddr $myhost $myhost.$suggested_domain $*"
	exit 0
}

# Fall back to the NIS domain, minus the first label.  If it is non-null,
# use it but recommend against it.  $2 is just informative, indicating whether
# we're checking the NIS domain.  $3 is to pass on.

check_nis_domain() {
	nisdomain=`domainname`
	realdomain=`echo $nisdomain | sed 's/[^.]*\.//'`
	if [ "x$realdomain" != "x" ] ; then
		echo "Hostname $1 can be fully qualified using NIS$2 domain"
		echo "	$nisdomain"
		echo "resulting in the name"
		echo "	$1.$realdomain"
		echo "but this is bad practice.\n"
		suggest_fix_and_exit $1 $realdomain $3
	fi
}

# Goal: try to fully qualify `hostname` as sendmail would.
# Algorithm (stop as soon as a name with a dot is found):
#    1. gethostbyname (simulate with getent hosts)
#    2. fall back to individual hosts: methods in nsswitch.conf, using
#       only those that are configured, in their configured order
#       * files (parse /etc/hosts directly)
#       * dns (parse nslookup output)
#       * nis (parse ypmatch output)
#    3. fall back to the NIS domain name.
# If none of the above succeed, give up.  Recommend:
#    a. the domain entry in /etc/resolv.conf, if one exists
#    b. "pick.some.domain"

myhostname=`hostname`

check_gethostbyname $myhostname

hosts_line=`sed -n -e 's/^hosts:\([^#]*\).*/\1/p' /etc/nsswitch.conf`
first_hosts_entry=`echo $hosts_line | awk '{print $1}'`
nis_domains=""

for entry in $hosts_line
do
	case $entry in
	files)
		check_hosts_file $myhostname
		;;
	dns)
		check_dns $myhostname
		;;
	nis)
		check_nis $myhostname
		nis_domains="$nis_domains nis"
		;;
	esac
done

for entry in $nis_domains
do
	case $entry in
	nis)
		check_nis_domain $myhostname "" $first_hosts_entry
		;;
	esac
done

realdomain=`awk '$1 ~ /^domain/ {print $2}' 2>/dev/null < /etc/resolv.conf`
case $realdomain in
*.*)
	# OK
	;;
*)
	realdomain="pick.some.domain"
	;;
esac

echo "Hostname $myhostname could not be fully qualified."
suggest_fix_and_exit $myhostname $realdomain $first_hosts_entry
