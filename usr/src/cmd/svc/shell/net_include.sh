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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T.
# All rights reserved.
#

# Print warnings to console
warn_failed_ifs() {
	echo "Failed to $1 interface(s):$2" >/dev/msglog
}

#
# shcat file
#   Simulates cat in sh so it doesn't need to be on the root filesystem.
#
shcat() {
        while [ $# -ge 1 ]; do
                while read i; do
                        echo "$i"
                done < $1
                shift
        done
}

#
# inet_list	list of IPv4 interfaces.
# inet6_list	list of IPv6 interfaces.
# ipmp_list	list of IPMP IPv4 interfaces.
# ipmp6_list	list of IPMP IPv6 interfaces.
# inet_plumbed	list of plumbed IPv4 interfaces.
# inet6_plumbed list of plumbed IPv6 interfaces.
# ipmp_created 	list of created IPMP IPv4 interfaces.
# ipmp6_created	list of created IPMP IPv6 interfaces.
# inet_failed	list of IPv4 interfaces that failed to plumb.
# inet6_failed	list of IPv6 interfaces that failed to plumb.
# ipmp_failed 	list of IPMP IPv4 interfaces that failed to be created.
# ipmp6_failed	list of IPMP IPv6 interfaces that failed to be created.
#
unset inet_list inet_plumbed inet_failed \
	inet6_list inet6_plumbed inet6_failed \
	ipmp_list ipmp_created ipmp_failed \
	ipmp6_list ipmp6_created ipmp6_failed

#
# get_physical interface
#
# Return physical interface corresponding to the given interface.
#
get_physical()
{
	ORIGIFS="$IFS"
	IFS="${IFS}:"
	set -- $1
	IFS="$ORIGIFS"

	echo $1
}

#
# get_logical interface
#
# Return logical interface number.  Zero will be returned
# if there is no explicit logical number.
#
get_logical()
{
	ORIGIFS="$IFS"
	IFS="${IFS}:"
	set -- $1
	IFS="$ORIGIFS"

	if [ -z "$2" ]; then
		echo 0
	else
		echo $2
	fi
}

#
# if_comp if1 if2
#
# Compare interfaces.  Do the physical interface names and logical interface
# numbers match?
#
if_comp()
{
	physical_comp $1 $2 && [ `get_logical $1` -eq `get_logical $2` ]
}

#
# physical_comp if1 if2
# 
# Do the two interfaces share a physical interface?
#
physical_comp()
{
	[ "`get_physical $1`" = "`get_physical $2`" ]
}

#
# in_list op item list
#
# Is "item" in the given list?  Use "op" to do the test, applying it to
# "item" and each member of the list in turn until it returns success.
#
in_list()
{
	op=$1
	item=$2
	shift 2

	while [ $# -gt 0 ]; do
		$op $item $1 && return 0
		shift
	done

	return 1
}

#
# get_inactive_ifname groupname
#
# Return the name of an inactive interface in `groupname', if one exists.
#
get_inactive_ifname()
{
	ORIGIFS="$IFS"
	/sbin/ipmpstat -gP -o groupname,interfaces |
	while IFS=: read groupname ifnames; do
		#
		# Skip other IPMP groups.
	        #
		[ "$groupname" != "$1" ] && continue

		#
		# Standby interfaces are always enclosed in ()'s, so look
		# for the first interface name starting with a "(", and
		# strip those off.
		#
		IFS=" "
		for ifname in $ifnames; do
			case "$ifname" in
			'('*)	IFS="()"
				echo $ifname
				IFS="$ORIGIFS"
				return
				;;
			*)	;;
			esac
		done
	done
	IFS="$ORIGIFS"
}

#
# get_groupifname groupname
#
# Return the IPMP meta-interface name for the group, if it exists.
#
get_groupifname()
{
	/sbin/ipmpstat -gP -o groupname,group | while IFS=: read name ifname; do
		if [ "$name" = "$1" ]; then
			echo "$ifname"
			return
		fi
	done
}

#
# create_ipmp ifname groupname type
#
# Helper function for create_groupifname() that returns zero if it's able
# to create an IPMP interface of the specified type and place it in the
# specified group, or non-zero otherwise.
#
create_ipmp()
{
	/sbin/ifconfig $1 >/dev/null 2>&1 && return 1
	/sbin/ifconfig $1 inet6 >/dev/null 2>&1 && return 1
	/sbin/ifconfig $1 $3 ipmp group $2 2>/dev/null
}

#
# create_groupifname groupname type 
#
# Create an IPMP meta-interface name for the group.  We only use this
# function if all of the interfaces in the group failed at boot and there
# were no /etc/hostname[6].<if> files for the IPMP meta-interface.
#
create_groupifname()
{
	#
	# This is a horrible way to count from 0 to 999, but in sh and
	# without necessarily having /usr mounted, what else can we do?
	#
	for a in "" 1 2 3 4 5 6 7 8 9; do
		for b in 0 1 2 3 4 5 6 7 8 9; do
			for c in 0 1 2 3 4 5 6 7 8 9; do
				# strip leading zeroes
				[ "$a" = "" ] && [ "$b" = 0 ] && b=""
				if create_ipmp ipmp$a$b$c $1 $2; then
					echo ipmp$a$b$c
					return
				fi
			done
		done
	done
}

#
# get_hostname_ipmpinfo interface type
#
# Return all requested IPMP keywords from hostname file for a given interface.
#
# Example:
#	get_hostname_ipmpinfo hme0 inet keyword [ keyword ... ]
#
get_hostname_ipmpinfo()
{
	case "$2" in
		inet)	file=/etc/hostname.$1
			;;
		inet6)	file=/etc/hostname6.$1
			;;
		*)
			return
			;;
	esac

	[ -r "$file" ] || return 

	type=$2
	shift 2

	#
	# Read through the hostname file looking for the specified
	# keywords.  Since there may be several keywords that cancel
	# each other out, the caller must post-process as appropriate.
	#
	while read line; do
		[ -z "$line" ] && continue
		/sbin/ifparse -s "$type" $line
	done < "$file" | while read one two; do
		for keyword in "$@"; do
			[ "$one" = "$keyword" ] && echo "$one $two"
		done
	done
}

#
# get_group_for_type interface type list
#
# Look through the set of hostname files associated with the same physical
# interface as "interface", and determine which group they would configure.
# Only hostname files associated with the physical interface or logical
# interface zero are allowed to set the group.
#
get_group_for_type()
{
	physical=`get_physical $1`
	type=$2
	group=""

	#
	# The last setting of the group is the one that counts, which is
	# the reason for the second while loop.
	#
	shift 2
	for ifname in "$@"; do
		if if_comp "$physical" $ifname; then 
			get_hostname_ipmpinfo $ifname $type group
		fi
	done | while :; do
		read keyword grname || {
			echo "$group"
			break
		}
		group="$grname"
	done
}

#
# get_standby_for_type interface type list
#
# Look through the set of hostname files associated with the same physical
# interface as "interface", and print the standby value ("standby",
# "-standby", or nothing).  Only hostname files associated with the
# physical interface or logical interface zero can set this flag.
#
get_standby_for_type()
{
	physical=`get_physical $1`
	type=$2

	#
	# The last setting of "standby" or "-standby" is the one that
	# counts, which is the reason for the second while loop.
	#
	shift 2
	for ifname in "$@"; do
		if if_comp "$physical" $ifname; then 
			get_hostname_ipmpinfo $ifname $type standby -standby
		fi
	done | while :; do
		read keyword || {
		    	echo "$iftype"
			break
		}
		iftype="$keyword"
	done
}

#
# get_group interface
#
# If there is both an inet and inet6 version of an interface, the group
# could be set in either set of hostname files.  Since inet6 is configured
# after inet, if there's a setting in both files, inet6 wins.
#
get_group()
{
	group=`get_group_for_type $1 inet6 $inet6_list`
	[ -z "$group" ] && group=`get_group_for_type $1 inet $inet_list`
	echo $group
}

#
# is_standby interface
#
# If there is both an inet and inet6 version of an interface, the
# "standby" or "-standby" flag could be set in either set of hostname
# files.  Since inet6 is configured after inet, if there's a setting in
# both files, inet6 wins.
#
is_standby()
{
	standby=`get_standby_for_type $1 inet6 $inet6_list`
	[ -z "$standby" ] && standby=`get_standby_for_type $1 inet $inet_list`
	[ "$standby" = "standby" ]
}

#
# doDHCPhostname interface
# Pass to this function the name of an interface.  It will return
# true if one should enable the use of DHCP client-side host name
# requests on the interface, and false otherwise.
#
doDHCPhostname()
{
	if [ -f /etc/dhcp.$1 ] && [ -f /etc/hostname.$1 ]; then
                set -- `shcat /etc/hostname.$1`
                [ $# -eq 2 -a "$1" = "inet" ]
                return $?      
        fi
        return 1
}

#
# inet_process_hostname processor [ args ]
#
# Process an inet hostname file.  The contents of the file
# are taken from standard input. Each line is passed
# on the command line to the "processor" command.
# Command line arguments can be passed to the processor.
#
# Examples:
#	inet_process_hostname /sbin/ifconfig hme0 < /etc/hostname.hme0
#	
#	inet_process_hostname /sbin/ifparse -f < /etc/hostname.hme0
#
# If there is only line in an hostname file we assume it contains
# the old style address which results in the interface being brought up 
# and the netmask and broadcast address being set ($inet_oneline_epilogue).
#
# If there are multiple lines we assume the file contains a list of
# commands to the processor with neither the implied bringing up of the
# interface nor the setting of the default netmask and broadcast address.
#
# Return non-zero if any command fails so that the caller may alert
# users to errors in the configuration.
#
inet_oneline_epilogue="netmask + broadcast + up"

inet_process_hostname()
{
	if doDHCPhostname $2; then
		:
	else
		#
		# Redirecting input from a file results in a sub-shell being
		# used, hence this outer loop surrounding the "multiple_lines"
		# and "ifcmds" variables.
		#
		while :; do
			multiple_lines=false
			ifcmds=""
			retval=0

			while read one rest; do
				if [ -n "$ifcmds" ]; then
					#
					# This handles the first N-1
					# lines of a N-line hostname file.
					#
					$* $ifcmds || retval=$?
					multiple_lines=true
				fi

				#
				# Strip out the "ipmp" keyword if it's the
				# first token, since it's used to control
				# interface creation, not configuration.
				#
				[ "$one" = ipmp ] && one=
				ifcmds="$one $rest"
			done

			#
			# If the hostname file is empty or consists of only
			# blank lines, break out of the outer loop without
			# configuring the newly plumbed interface.
			#
			[ -z "$ifcmds" ] && return $retval
			if [ $multiple_lines = false ]; then
				# The traditional one-line hostname file.
				ifcmds="$ifcmds $inet_oneline_epilogue"
			fi

			#
			# This handles either the single-line case or
			# the last line of the N-line case.
			#
			$* $ifcmds || return $?
			return $retval
		done
	fi
}

#
# inet6_process_hostname processor [ args ]
#
# Process an inet6 hostname file.  The contents of the file
# are taken from standard input. Each line is passed
# on the command line to the "processor" command.
# Command line arguments can be passed to the processor.
#
# Examples:
#	inet6_process_hostname /sbin/ifconfig hme0 inet6 < /etc/hostname6.hme0
#	
#	inet6_process_hostname /sbin/ifparse -f inet6 < /etc/hostname6.hme0
#
# Return non-zero if any of the commands fail so that the caller may alert
# users to errors in the configuration.
#
inet6_process_hostname()
{
    	retval=0
	while read one rest; do
		#
	    	# See comment in inet_process_hostname for details.
	        #
		[ "$one" = ipmp ] && one=
		ifcmds="$one $rest"

		if [ -n "$ifcmds" ]; then
			$* $ifcmds || retval=$?
		fi
	done
	return $retval
}

#
# Process interfaces that failed to plumb.  Find the IPMP meta-interface
# that should host the addresses.  For IPv6, only static addresses defined
# in hostname6 files are moved, autoconfigured addresses are not moved.
#
# Example:
#	move_addresses inet6
#
move_addresses()
{
	type="$1"
	eval "failed=\"\$${type}_failed\""
	eval "list=\"\$${type}_list\""
	process_func="${type}_process_hostname"
	processed=""

	if [ "$type" = inet ]; then
	        typedesc="IPv4"
		zaddr="0.0.0.0"
		hostpfx="/etc/hostname"
	else
	        typedesc="IPv6"
		zaddr="::"
		hostpfx="/etc/hostname6"
	fi

	echo "Moving addresses from missing ${typedesc} interface(s):\c" \
	    >/dev/msglog

	for ifname in $failed; do
		in_list if_comp $ifname $processed && continue

		group=`get_group $ifname`
		if [ -z "$group" ]; then
			in_list physical_comp $ifname $processed || { 
				echo " $ifname (not moved -- not" \
				    "in an IPMP group)\c" >/dev/msglog
				processed="$processed $ifname"
			}
			continue
		fi

		#
		# Lookup the IPMP meta-interface name.  If one doesn't exist,
		# create it.
		#
		grifname=`get_groupifname $group`
		[ -z "$grifname" ] && grifname=`create_groupifname $group $type`

		#
		# The hostname files are processed twice.  In the first
		# pass, we are looking for all commands that apply
		# to the non-additional interface address.  These may be
		# scattered over several files.  We won't know
		# whether the address represents a failover address
		# or not until we've read all the files associated with the
		# interface.
		#
		# In the first pass through the hostname files, all
		# additional logical interface commands are removed.
		# The remaining commands are concatenated together and
		# passed to ifparse to determine whether the 
		# non-additional logical interface address is a failover
		# address.  If it as a failover address, the
		# address may not be the first item on the line,
		# so we can't just substitute "addif" for "set".
		# We prepend an "addif $zaddr" command, and let
		# the embedded "set" command set the address later.	
		#
		/sbin/ifparse -f $type `
			for item in $list; do
				if_comp $ifname $item && $process_func \
				    /sbin/ifparse $type < $hostpfx.$item 
			done | while read three four; do
				[ "$three" != addif ] && echo "$three $four \c"
			done` | while read one two; do
				[ -z "$one" ] && continue
				[ "$one $two" = "$inet_oneline_epilogue" ] && \
				    continue
				line="addif $zaddr $one $two"
				/sbin/ifconfig $grifname $type $line >/dev/null
			done

		#
		# In the second pass, look for the the "addif" commands
		# that configure additional failover addresses.  Addif
		# commands are not valid in logical interface hostname
		# files.
		#
		if [ "$ifname" = "`get_physical $ifname`" ]; then
			$process_func /sbin/ifparse -f $type < $hostpfx.$ifname \
			| while read one two; do
				[ "$one" = addif ] && \
					/sbin/ifconfig $grifname $type \
				    	    addif $two >/dev/null
			done
		fi

		#
		# Check if this was an active interface in the group.  If so,
		# activate another IP interface (if possible)
		#
		is_standby $ifname || inactive=`get_inactive_ifname $group`
		[ -n "$inactive" ] && /sbin/ifconfig $inactive $type -standby

		in_list physical_comp $ifname $processed || { 
			processed="$processed $ifname"
			echo " $ifname (moved to $grifname\c"	   > /dev/msglog
			if [ -n "$inactive" ]; then
				echo " and cleared 'standby' on\c" > /dev/msglog
				echo " $inactive to compensate\c"  > /dev/msglog
			fi
			echo ")\c"				   > /dev/msglog
		}
		inactive=""
	done
	echo "." >/dev/msglog
}

#
# if_configure type class interface_list
#
# Configure all of the interfaces of type `type' (e.g., "inet6") in
# `interface_list' according to their /etc/hostname[6].* files.  `class'
# describes the class of interface (e.g., "IPMP"), as a diagnostic aid.
# For inet6 interfaces, the interface is also brought up.
#
if_configure()
{
	fail=
	type=$1
	class=$2
	process_func=${type}_process_hostname
	shift 2

	if [ "$type" = inet ]; then
	        desc="IPv4"
		hostpfx="/etc/hostname"
	else
	        desc="IPv6"
		hostpfx="/etc/hostname6"
	fi
	[ -n "$class" ] && desc="$class $desc"

	echo "configuring $desc interfaces:\c"
	while [ $# -gt 0 ]; do
		$process_func /sbin/ifconfig $1 $type < $hostpfx.$1 >/dev/null
		if [ $? != 0 ]; then
			fail="$fail $1"
		elif [ "$type" = inet6 ]; then
		    	/sbin/ifconfig $1 inet6 up || fail="$fail $1"
		fi
		echo " $1\c"
		shift
	done
	echo "."

	[ -n "$fail" ] && warn_failed_ifs "configure $desc" "$fail"
}

#
# net_reconfigure is called from the network/physical service (by the
# net-physical and net-nwam method scripts) to perform tasks that only
# need to be done during a reconfigure boot.  This needs to be
# isolated in a function since network/physical has two instances
# (default and nwam) that have distinct method scripts that each need
# to do these things.
#
net_reconfigure ()
{
	#
	# Is this a reconfigure boot?  If not, then there's nothing
	# for us to do.
	#
	reconfig=`svcprop -c -p system/reconfigure system/svc/restarter:default`
	if [ $? -ne 0 -o "$reconfig" = false ]; then
		return 0
	fi

	#
	# Ensure that the datalink-management service is running since
	# manifest-import has not yet run for a first boot after
	# upgrade.  We wouldn't need to do that if manifest-import ran
	# earlier in boot, since there is an explicit dependency
	# between datalink-management and network/physical.
	#
	svcadm enable -ts network/datalink-management:default

	#
	# There is a bug in SMF which causes the svcadm command above
	# to exit prematurely (with an error code of 3) before having
	# waited for the service to come online after having enabled
	# it.  Until that bug is fixed, we need to have the following
	# loop to explicitly wait for the service to come online.
	#
	i=0
	while [ $i -lt 30 ]; do
		i=`expr $i + 1`
		sleep 1
		state=`svcprop -p restarter/state \
		    network/datalink-management:default 2>/dev/null`
		if [ $? -ne 0 ]; then
			continue
		elif [ "$state" = "online" ]; then
			break
		fi
	done
	if [ "$state" != "online" ]; then
		echo "The network/datalink-management service \c"
		echo "did not come online."
		return 1
	fi

	#
	# Initialize the set of physical links, and validate and
	# remove all the physical links which were removed during the
	# system shutdown.
	#
	/sbin/dladm init-phys
	return 0
}
