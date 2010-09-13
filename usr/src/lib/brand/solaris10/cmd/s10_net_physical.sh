#!/sbin/sh
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

# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T.
# All rights reserved.
#
# THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF AT&T
# The copyright notice above does not evidence any
# actual or intended publication of such source code.
#

. /lib/svc/share/smf_include.sh
. /lib/svc/share/net_include.sh

#
# This file replaces the Solaris 10 net-physical script in S10C at
# boot time. Any S10C specific changes to net-physical script needs
# to be made in this file. 
#

#
# In a shared-IP zone we need this service to be up, but all of the work
# it tries to do is irrelevant (and will actually lead to the service
# failing if we try to do it), so just bail out.
# In exclusive-IP zones we proceed.
#
if [ `/sbin/zonename -t` = shared ]; then
	exit 0
fi

# Print warnings to console
warn_failed_ifs() {
	echo "Failed to $1 interface(s): $2" >/dev/msglog
}

#
# Cause ifconfig to not automatically start in.mpathd when IPMP groups are
# configured.  This is not strictly necessary but makes it so that in.mpathd
# will always be started explicitly from /etc/init.d/inetinit, when we're
# sure that /usr is mounted.
#
SUNW_NO_MPATHD=; export SUNW_NO_MPATHD

smf_netstrategy

#
# If the system was net booted by DHCP, hand DHCP management off to the
# DHCP agent (ifconfig communicates to the DHCP agent through the
# loopback interface).
#
if [ -n "$_INIT_NET_IF" -a "$_INIT_NET_STRATEGY" = "dhcp" ]; then
	/sbin/dhcpagent -a
fi

#
# For IPv4 interfaces that were configured by the kernel and not
# configured by DHCP, reset the netmask using the local "/etc/netmasks"
# file if one exists, and then reset the broadcast address based on
# the netmask.
#
/sbin/ifconfig -auD4 netmask + broadcast +

#
# All the IPv4 and IPv6 interfaces are plumbed before doing any
# interface configuration.  This prevents errors from plumb failures
# getting mixed in with the configured interface lists that the script
# outputs.
#
# Moreover in S10C, we process IPMP interfaces before non-IPMP
# interfaces to avoid accidental implicit IPMP group creation.
# Therefore we keep track of IPMP and non-IPMP interfaces in two
# different lists i.e. ipmp[6]_list vs inet[6]_list.

#
# Get the list of IPv4 interfaces to configure by breaking
# /etc/hostname.* into separate args by using "." as a shell separator
# character.
#
interface_names="`echo /etc/hostname.*[0-9] 2>/dev/null`"
if [ "$interface_names" != "/etc/hostname.*[0-9]" ]; then
	ORIGIFS="$IFS"
	IFS="$IFS."
	set -- $interface_names
	IFS="$ORIGIFS"
	while [ $# -ge 2 ]; do
		shift
		if [ "$1" = "xx0" ]; then
			#
			# For some unknown historical reason the xx0
			# ifname is ignored.
			#
			shift
			continue
		fi
		if [ $# -gt 1 -a "$2" != "/etc/hostname" ]; then
			while [ $# -gt 1 -a "$1" != "/etc/hostname" ]; do
				shift
			done
		else
			read one rest < /etc/hostname.$1
			if [ "$one" = ipmp ]; then
				ipmp_list="$ipmp_list $1"
			else
				inet_list="$inet_list $1"
			fi
			shift
		fi
	done
fi

#
# Get the list of IPv6 interfaces to configure by breaking
# /etc/hostname6.* into separate args by using "." as a shell separator
# character.
#
interface_names="`echo /etc/hostname6.*[0-9] 2>/dev/null`"
if [ "$interface_names" != "/etc/hostname6.*[0-9]" ]; then
	ORIGIFS="$IFS"
	IFS="$IFS."
	set -- $interface_names
	IFS="$ORIGIFS"
	while [ $# -ge 2 ]; do
		shift
		if [ $# -gt 1 -a "$2" != "/etc/hostname6" ]; then
			while [ $# -gt 1 -a "$1" != "/etc/hostname6" ]; do
				shift
			done
		else
			read one rest < /etc/hostname6.$1
			if [ "$one" = ipmp ]; then
				ipmp6_list="$ipmp6_list $1"
			else
				inet6_list="$inet6_list $1"
			fi
			shift
		fi
	done
fi

#
# Create all of the IPv4 IPMP interfaces.
#
if [ -n "$ipmp_list" ]; then
	set -- $ipmp_list
	while [ $# -gt 0 ]; do
		if /sbin/ifconfig $1 ipmp; then
			ipmp_created="$ipmp_created $1"
		else
			ipmp_failed="$ipmp_failed $1"
		fi
		shift
	done
	[ -n "$ipmp_failed" ] && warn_failed_ifs "create IPv4 IPMP" \
	    "$ipmp_failed"
fi

#
# Step through the IPv4 interface list and try to plumb every interface.
# Generate list of plumbed and failed IPv4 interfaces.
#
if [ -n "$inet_list" ]; then
	set -- $inet_list
	while [ $# -gt 0 ]; do
		/sbin/ifconfig $1 plumb
		if /sbin/ifconfig $1 inet >/dev/null 2>&1; then
			inet_plumbed="$inet_plumbed $1"
		else
			inet_failed="$inet_failed $1"
		fi
		shift
	done
	[ -n "$inet_failed" ] && warn_failed_ifs "plumb IPv4" $inet_failed
fi

#
# Step through the IPv6 interface list and plumb every interface.
# Generate list of plumbed and failed IPv6 interfaces.  Each plumbed
# interface will be brought up later, after processing any contents of
# the /etc/hostname6.* file.
#
if [ -n "$inet6_list" ]; then
	set -- $inet6_list
	while [ $# -gt 0 ]; do
		/sbin/ifconfig $1 inet6 plumb
		if /sbin/ifconfig $1 inet6 >/dev/null 2>&1; then
			inet6_plumbed="$inet6_plumbed $1"
		else
			inet6_failed="$inet6_failed $1"
		fi
		shift
	done
	[ -n "$inet6_failed" ] && warn_failed_ifs "plumb IPv6" $inet6_failed
fi

#
# Create all of the IPv6 IPMP interfaces.
#
if [ -n "$ipmp6_list" ]; then
	set -- $ipmp6_list
	while [ $# -gt 0 ]; do
		if /sbin/ifconfig $1 inet6 ipmp; then
			ipmp6_created="$ipmp6_created $1"
		else
			ipmp6_failed="$ipmp6_failed $1"
		fi
		shift
	done
	[ -n "$ipmp6_failed" ] && warn_failed_ifs "create IPv6 IPMP" \
	    "$ipmp6_failed"
fi

#
# Process IPMP interfaces before non-IPMP interfaces
# to avoid accidental implicit IPMP group creation.
#
if [ -n "$ipmp_created" ]; then
	i4s_fail=
	echo "configuring IPv4 IPMP interfaces:\c"
	set -- $ipmp_created
	while [ $# -gt 0 ]; do
		inet_process_hostname /sbin/ifconfig $1 inet \
		    </etc/hostname.$1 >/dev/null
		[ $? != 0 ] && i4s_fail="$i4s_fail $1"
		echo " $1\c"
		shift
	done
	echo "."
	[ -n "$i4s_fail" ] && warn_failed_ifs "configure IPv4 IPMP" \
	    $i4s_fail
fi
	
if [ -n "$ipmp6_created" ]; then
	i6_fail=
	echo "configuring IPv6 IPMP interfaces:\c"
	set -- $ipmp6_created
	while [ $# -gt 0 ]; do
		inet6_process_hostname /sbin/ifconfig $1 inet6 \
		    </etc/hostname6.$1 >/dev/null && 
		    /sbin/ifconfig $1 inet6 up
		[ $? != 0 ] && i6_fail="$i6_fail $1"
		echo " $1\c"
		shift
	done
	echo "."
	[ -n "$i6_fail" ] && warn_failed_ifs "configure IPv6 IPMP" \
	    $i6_fail
fi

#
# Process the /etc/hostname.* files of plumbed IPv4 interfaces.  If an
# /etc/hostname file is not present or is empty, the ifconfig auto-dhcp
# / auto-revarp command will attempt to set the address, later.
#
# If /etc/hostname.lo0 exists the loop below will do additional
# configuration of lo0.
#
if [ -n "$inet_plumbed" ]; then
	i4s_fail=
	echo "configuring IPv4 interfaces:\c"
	set -- $inet_plumbed
	while [ $# -gt 0 ]; do
		l3protect=`/sbin/ifconfig $1|grep -c L3PROTECT`
		if [ $l3protect != 0 ]; then
			echo "Ignoring /etc/hostname.$1" > /dev/msglog
		else
			inet_process_hostname /sbin/ifconfig $1 inet \
			    </etc/hostname.$1 >/dev/null
			[ $? != 0 ] && i4s_fail="$i4s_fail $1"
			echo " $1\c"
		fi
		shift
	done
	echo "."
	[ -n "$i4s_fail" ] && warn_failed_ifs "configure IPv4" $i4s_fail
fi

#
# Process the /etc/hostname6.* files of plumbed IPv6 interfaces.  After
# processing the hostname6 file, bring the interface up.  If
# /etc/hostname6.lo0 exists the loop below will do additional
# configuration of lo0.
#
if [ -n "$inet6_plumbed" ]; then
	i6_fail=
	echo "configuring IPv6 interfaces:\c"
	set -- $inet6_plumbed
	while [ $# -gt 0 ]; do
		l3protect=`/sbin/ifconfig $1|grep -c L3PROTECT`
		if [ $l3protect != 0 ]; then
			echo "Ignoring /etc/hostname6.$1" > /dev/msglog
		else
			inet6_process_hostname /sbin/ifconfig $1 inet6 \
			    </etc/hostname6.$1 >/dev/null && 
			    /sbin/ifconfig $1 inet6 up
			[ $? != 0 ] && i6_fail="$i6_fail $1"
			echo " $1\c"
		fi
		shift
	done
	echo "."
	[ -n "$i6_fail" ] && warn_failed_ifs "configure IPv6" $i6_fail
fi

# Run DHCP if requested. Skip boot-configured interface.
interface_names="`echo /etc/dhcp.*[0-9] 2>/dev/null`"
if [ "$interface_names" != '/etc/dhcp.*[0-9]' ]; then
	#
	# First find the primary interface. Default to the first
	# interface if not specified. First primary interface found
	# "wins". Use care not to "reconfigure" a net-booted interface
	# configured using DHCP. Run through the list of interfaces
	# again, this time trying DHCP.
	#
	i4d_fail=
	firstif=
	primary=
	ORIGIFS="$IFS"
	IFS="${IFS}."
	set -- $interface_names

	while [ $# -ge 2 ]; do
		shift
		[ -z "$firstif" ] && firstif=$1

		for i in `shcat /etc/dhcp\.$1`; do
			if [ "$i" = primary ]; then
				primary=$1
				break
			fi
		done

		[ -n "$primary" ] && break
		shift
	done

	[ -z "$primary" ] && primary="$firstif"
	cmdline=`shcat /etc/dhcp\.${primary}`

	if [ "$_INIT_NET_IF" != "$primary" ]; then
		echo "starting DHCP on primary interface $primary"
		/sbin/ifconfig $primary auto-dhcp primary $cmdline
		# Exit code 4 means ifconfig timed out waiting for dhcpagent
		[ $? != 0 ]  && [ $? != 4 ] && i4d_fail="$i4d_fail $primary"
	fi

	set -- $interface_names

	while [ $# -ge 2 ]; do
		shift
		cmdline=`shcat /etc/dhcp\.$1`
		if [ "$1" != "$primary" -a \
			"$1" != "$_INIT_NET_IF"  ]; then
			echo "starting DHCP on interface $1"
			/sbin/ifconfig $1 dhcp start wait 0 $cmdline
			# Exit code can't be timeout when wait is 0
			[ $? != 0 ] && i4d_fail="$i4d_fail $1"
		fi
		shift
	done
	IFS="$ORIGIFS"
	unset ORIGIFS
	[ -n "$i4d_fail" ] && warn_failed_ifs "configure IPv4 DHCP" $i4d_fail
fi

# In order to avoid bringing up the interfaces that have
# intentionally been left down, perform RARP only if the system
# has no configured hostname in /etc/nodename
hostname="`shcat /etc/nodename 2>/dev/null`"
if [ "$_INIT_NET_STRATEGY" = "rarp" -o -z "$hostname" ]; then
        /sbin/ifconfig -adD4 auto-revarp netmask + broadcast + up
fi

#
# Process IPv4 and IPv6 interfaces that failed to plumb.  Find an
# alternative interface to host the addresses.
#
[ -n "$inet_failed" ] && move_addresses inet

[ -n "$inet6_failed" ] && move_addresses inet6

#
# If the /etc/defaultrouter file exists, process it now so that the next
# stage of booting will have access to NFS.
#
if [ -f /etc/defaultrouter ]; then
	while read router rubbish; do
		case "$router" in
			'#'* | '') ;;	#  Ignore comments, empty lines
			*)	/sbin/route -n add default -gateway $router ;;
		esac
	done </etc/defaultrouter
fi

#
# We tell smf this service is online if any of the following is true:
# - no interfaces were configured for plumbing and no DHCP failures
# - there are any DHCP interfaces started
# - any non-loopback, non-DHCP IPv4 interfaces are up and have a non-zero
#   address
# - any non-loopback IPv6 interfaces are up
#
# If we weren't asked to configure any interfaces, exit
if [ -z "$inet_list" ] && [ -z "$inet6_list" ]; then
	# Config error if DHCP was attempted without plumbed interfaces
	[ -n "$i4d_fail" ] && exit $SMF_EXIT_ERR_CONFIG
	exit $SMF_EXIT_OK
fi

# Any DHCP interfaces?
[ -n "`/sbin/ifconfig -a4 dhcp status 2>/dev/null`" ] && exit $SMF_EXIT_OK

# Any non-loopback, non-DHCP IPv4 interfaces with usable addresses up?
if [ -n "`/sbin/ifconfig -a4uD`" ]; then
    	/sbin/ifconfig -a4uD | while read intf addr rest; do
		[ $intf = inet ] && [ $addr != 127.0.0.1 ] &&
		[ $addr != 0.0.0.0 ] && exit 0
	done && exit $SMF_EXIT_OK
fi

# Any non-loopback IPv6 interfaces up?
if [ -n "`/sbin/ifconfig -au6`" ]; then
	/sbin/ifconfig -au6 | while read intf addr rest; do
		[ $intf = inet6 ] && [ $addr != ::1/128 ] && exit 0
	done && exit $SMF_EXIT_OK
fi

# This service was supposed to configure something yet didn't.  Exit
# with config error.
exit $SMF_EXIT_ERR_CONFIG
