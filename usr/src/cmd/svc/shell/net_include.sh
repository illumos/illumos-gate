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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T.
# All rights reserved.
#

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
# Inet_list, list of IPv4 interfaces.
# Inet_plumbed, list of plumbed IPv4 interfaces.
# Inet_failed, list of IPv4 interfaces that failed to plumb.
# Inet6_list, list of IPv6 interfaces.
# Inet6_plumbed, list of plumbed IPv6 interfaces.
# Inet6_failed, list of IPv6 interfaces that failed to plumb.
#
unset inet_list inet_plumbed inet_failed \
	inet6_list inet6_plumbed inet6_failed
#
# get_physical interface
#
# Return physical interface corresponding to the given logical
# interface.
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
# if there is no explicit logical device number.
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
# Compare Interfaces.  Do the physical interface names and logical interface
# numbers match?
#
if_comp()
{
	[ "`get_physical $1`" = "`get_physical $2`" ] && \
		[ `get_logical $1` -eq `get_logical $2` ]
}
	
#
# physical_comp if1 if2
# 
# Do the two devices share a physical interface?
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
# get_group_from_hostname interface type
#
# Return all group settings from hostname file for a given interface.
#
# Example:
#	get_group_from_hostname  hme0 inet
#
get_group_from_hostname()
{
	case "$2" in
		inet) file=/etc/hostname.$1
			;;
		inet6) file=/etc/hostname6.$1
			;;
		*)
			return
			;;
	esac

	[ -r "$file" ] || return 

	#
	# Read through the hostname file looking for group settings
	# There may be several group settings in the file.  It is up
	# to the caller to pick the right one (i.e. the last one).
	#
	while read line; do
		[ -z "$line" ] && continue
		/sbin/ifparse -s "$2" $line
	done < "$file" | while read one two three; do
		[ "$one" = "group" ] && echo "$two"
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
	while [ $# -gt 0 ]; do
		if if_comp "$physical" $1; then 
			get_group_from_hostname $1 $type
		fi
		shift
	done | while :; do
		read next || {
			echo "$group"
			break
		}
		group="$next"
	done
}

#
# get_group interface [ configured | failed ]
#
# If there is both an inet and inet6 version of an interface, the group
# could be set in either set of hostname files.
#
# Inet6 is configured after inet, so if the group is set in both
# sets of hostname files, the inet6 file wins.
#
# The "configured" argument should be used to get the group for
# an interface that has been plumbed into the stack and configured.  Use
# the "failed" argument to get the group for an interface that failed to
# plumb.
#
get_group()
{
	group=""

	case "$2" in
		configured)
			group=`get_group_for_type $1 inet6 $inet6_plumbed`
			;;
		failed)
			group=`get_group_for_type $1 inet6 $inet6_list`
			;;
		*)
			return
			;;
	esac

	if [ -z "$group" ]; then
		if [ "$2" = configured ]; then
			group=`get_group_for_type $1 inet $inet_plumbed`
		else
			group=`get_group_for_type $1 inet $inet_list`
		fi
	fi

	echo $group
}

#
# get_standby_from_hostname interface type
#
# Return any "standby" or "-standby" flags in the hostname file.
#
# Example:
#	get_standby_from_hostname hme0 inet6
#
#
get_standby_from_hostname()
{
	case "$2" in
		inet) file=/etc/hostname.$1
			;;
		inet6) file=/etc/hostname6.$1
			;;
		*)
			return
			;;
	esac

	[ -r "$file" ] || return

	#
	# There may be several instances of the "standby" and
	# "-standby" flags in the hostname file.  It is up to
	# the caller to pick the correct one.
	#
	while read line; do
		[ -z "$line" ] && continue
		/sbin/ifparse -s "$2" $line
	done < "$file" | while read one two; do
		[ "$one" = "standby" ] || [ "$one" = "-standby" ] \
			&& echo "$one"
	done 
}

#
# get_standby_for_type interface type plumbed_list
#
# Look through the set of hostname files associated with the same physical
# interface as "interface", and determine whether they would configure
# the interface as a standby interface.
#
get_standby_for_type()
{

	physical=`get_physical $1`
	type=$2

	final=""

	#
	# The last "standby" or "-standby" flag is the one that counts,
	# which is the reason for the second while loop.
	#
	shift 2
	while [ $# -gt 0 ]; do
		if [ "`get_physical $1`" = "$physical" ]; then 
			get_standby_from_hostname $1 $type
		fi
		shift
	done | while :; do
		read next || {
			echo "$final"
			break
		}
		final="$next"
	done
}

#
# is_standby interface
#
# Determine whether a configured interface is a standby interface.
#
# Both the inet and inet6 hostname file sets must be checked.
# If "standby" or "-standby" is set in the inet6 hostname file set,
# don't bother looking at the inet set.
#
is_standby()
{
	standby=`get_standby_for_type $1 inet6 $inet6_plumbed`

	if [ -z "$standby" ]; then
		standby=`get_standby_for_type $1 inet $inet_plumbed`
	fi

	# The return value is the value of the following test.
	[ "$standby" = "standby" ]
}

#
# get_alternate interface plumbed_list
#
# Look for a plumbed interface in the same group as "interface".
# A standby interface is preferred over a non-standby interface.
#
# Example:
#	get_alternate hme0 $inet_plumbed
#
get_alternate()
{
	mygroup=`get_group $1 failed`
	[ -z "$mygroup" ] && return

	maybe=""

	shift
	while [ $# -gt 0 ]; do
		group=`get_group $1 configured`
		if [ "$group" = "$mygroup" ]; then
			if is_standby $1; then
				get_physical $1
				return
			else
				[ -z "$maybe" ] && maybe=$1
			fi
		fi
		shift
	done

	get_physical $maybe
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
# and the netmask and broadcast address being set.
#
# If there are multiple lines we assume the file contains a list of
# commands to the processor with neither the implied bringing up of the
# interface nor the setting of the default netmask and broadcast address.
#
# Return non-zero if any command fails so that the caller may alert
# users to errors in the configuration.
#
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

			while read line; do
				if [ -n "$ifcmds" ]; then
					#
					# This handles the first N-1
					# lines of a N-line hostname file.
					#
					$* $ifcmds || retval=$?
					multiple_lines=true
				fi
				ifcmds="$line"
			done

			#
			# If the hostname file is empty or consists of only
			# blank lines, break out of the outer loop without
			# configuring the newly plumbed interface.
			#
			[ -z "$ifcmds" ] && return $retval
			if [ $multiple_lines = false ]; then
				# The traditional single-line hostname file.
				ifcmds="$ifcmds netmask + broadcast + up"
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
	while read ifcmds; do
		if [ -n "$ifcmds" ]; then
			$* $ifcmds || retval=$?
		fi
	done
	return $retval
}

#
# Process interfaces that failed to plumb.  Find an alternative
# interface to host the addresses.  For IPv6, only static addresses
# defined in hostname6 files are moved, autoconfigured addresses are
# not moved.
#
# Example:
#	move_addresses inet6
#
move_addresses()
{
	type="$1"
	eval "failed=\"\$${type}_failed\""
	eval "plumbed=\"\$${type}_plumbed\""
	eval "list=\"\$${type}_list\""
	process_hostname="${type}_process_hostname"
	processed=""

	if [ "$type" = inet ]; then
		echo "moving addresses from failed IPv4 interfaces:\c"
		zaddr="0.0.0.0"
		hostpfx="/etc/hostname"
	else
		echo "moving addresses from failed IPv6 interfaces:\c"
		zaddr="::"
		hostpfx="/etc/hostname6"
	fi

	set -- $failed
	while [ $# -gt 0 ]; do
		in_list if_comp $1 $processed && { shift; continue; }

		alternate="`get_alternate $1 $plumbed`"
		if [ -z "$alternate" ]; then
			in_list physical_comp $1 $processed || { 
				echo " $1 (couldn't move, no" \
					"alternative interface)\c"
				processed="$processed $1"
			}
			shift
			continue
		fi
		#
		# The hostname files are processed twice.  In the first
		# pass, we are looking for all commands that apply
		# to the non-additional interface address.  These may be
		# scattered over several files.  We won't know
		# whether the address represents a failover address
		# or not until we've read all the files associated with the
		# interface.

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
					if_comp $1 $item && \
					$process_hostname /sbin/ifparse \
					$type < $hostpfx.$item 
					done  | while read three four; do
					[ "$three" != addif ] && \
						echo "$three $four \c"
				done` | while read one two; do
					[ -z "$one" ] && continue
					line="addif $zaddr $one $two"
					/sbin/ifconfig $alternate $type \
						-standby $line >/dev/null
				done

		#
		# In the second pass, look for the the "addif" commands
		# that configure additional failover addresses.  Addif
		# commands are not valid in logical interface hostname
		# files.
		#
		if [ "$1" = "`get_physical $1`" ]; then
			$process_hostname /sbin/ifparse -f $type \
			<$hostpfx.$1 | while read one two; do
			[ "$one" = addif ] && \
				/sbin/ifconfig $alternate $type -standby \
				    addif $two >/dev/null
			done
		fi

		in_list physical_comp $1 $processed || { 
			echo " $1 (moved to $alternate)\c"
			processed="$processed $1"
		}
		shift
	done
	echo "."
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
