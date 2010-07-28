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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T.
# All rights reserved.
#

NET_INADDR_ANY="0.0.0.0"
NET_IN6ADDR_ANY_INIT="::0"

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

net_record_err()
{
	message=$1
	err=$2

	echo "$message" | smf_console
	if [ $err -ne 0 ]; then
		echo "Error code = $err" | smf_console
	fi
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
# Given the interface name and the address family (inet or inet6), determine
# whether this is a VRRP VNIC.
#
# This is used to determine whether to bring the interface up
#
not_vrrp_interface() {
	macaddrtype=`/sbin/dladm show-vnic $1 -o MACADDRTYPE -p 2>/dev/null`

	case "$macaddrtype" in
	'vrrp'*''$2'')	vrrp=1
			;;
        *)		vrrp=0
			;;
	esac
	return $vrrp
}

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
# Note that if the interface is a VRRP interface, do not bring the address
# up ($inet_oneline_epilogue_no_up).
#
# If there are multiple lines we assume the file contains a list of
# commands to the processor with neither the implied bringing up of the
# interface nor the setting of the default netmask and broadcast address.
#
# Return non-zero if any command fails so that the caller may alert
# users to errors in the configuration.
#
inet_oneline_epilogue_no_up="netmask + broadcast +"
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
				#
				# The traditional one-line hostname file.
				# Note that we only bring it up if the
				# interface is not a VRRP VNIC.
				#
				if not_vrrp_interface $2 $3; then
					estr="$inet_oneline_epilogue"
				else
					estr="$inet_oneline_epilogue_no_up"
				fi
				ifcmds="$ifcmds $estr"
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
		# pass, we are looking for all commands that apply to the
		# non-additional interface address.  These may be
		# scattered over several files.  We won't know whether the
		# address represents a failover address or not until we've
		# read all the files associated with the interface.
		#
		# In the first pass through the hostname files, all
		# additional logical interface commands are removed.  The
		# remaining commands are concatenated together and passed
		# to ifparse to determine whether the non-additional
		# logical interface address is a failover address.  If it
		# as a failover address, the address may not be the first
		# item on the line, so we can't just substitute "addif"
		# for "set".  We prepend an "addif $zaddr" command, and
		# let the embedded "set" command set the address later.
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

		in_list physical_comp $ifname $processed || { 
			processed="$processed $ifname"
			echo " $ifname (moved to $grifname)\c" > /dev/msglog
		}
	done
	echo "." >/dev/msglog
}

#
# ipadm_from_gz_if ifname
#
# Return true if we are in a non-global zone and Layer-3 protection of
# IP addresses is being enforced on the interface by the global zone
#
ipadm_from_gz_if()
{ 
	pif=`/sbin/ipadm show-if -o persistent -p $1 2>/dev/null | egrep '4|6'`
	if smf_is_globalzone || ![[ $pif == *4* || $pif == *6* ]]; then
		return 1
	else
		#
		# In the non-global zone, plumb the interface to show current
		# flags and check if Layer-3 protection has been enforced by
		# the global zone. Note that this function may return
		# with a plumbed interface. Ideally, we would not have to
		# plumb the interface to check l3protect, but since we
		# the `allowed-ips' datalink property cannot currently be
		# examined in any other way from the non-global zone, we
		# resort to plumbing the interface
		# 
		/sbin/ifconfig $1 plumb > /dev/null 2>&1
		l3protect=`/sbin/ipadm show-if -o current -p $1|grep -c 'Z'`
		if [ $l3protect = 0 ]; then
			return 1
		else
			return 0
		fi
	fi
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
			ipadm_from_gz_if $1
			if [ $? != 0 ]; then
				fail="$fail $1"
			fi
		elif [ "$type" = inet6 ]; then
			#
			# only bring the interface up if it is not a
			# VRRP VNIC
			#
			if not_vrrp_interface $1 $type; then
			    	/sbin/ifconfig $1 inet6 up || fail="$fail $1"
			fi
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
	reconfig=`svcprop -c -p system/reconfigure \
	    system/svc/restarter:default 2>/dev/null`
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

#
# Check for use of the default "Port VLAN Identifier" (PVID) -- VLAN 1.
# If there is one for a given interface, then warn the user and force the
# PVID to zero (if it's not already set).  We do this by generating a list
# of interfaces with VLAN 1 in use first, and then parsing out the
# corresponding base datalink entries to check for ones without a
# "default_tag" property.
#
update_pvid()
{
	datalink=/etc/dladm/datalink.conf

	(
		# Find datalinks using VLAN 1 explicitly
		# configured by dladm
		/usr/bin/nawk '
			/^#/ || NF < 2 { next }
			{ linkdata[$1]=$2; }
			/;vid=int,1;/ {
				sub(/.*;linkover=int,/, "", $2);
				sub(/;.*/, "", $2);
				link=linkdata[$2];
				sub(/name=string,/, "", link);
				sub(/;.*/, "", link);
				print link;
			}' $datalink
	) | ( /usr/bin/sort -u; echo END; cat $datalink ) | /usr/bin/nawk '
	    /^END$/ { state=1; }
	    state == 0 { usingpvid[++nusingpvid]=$1; next; }
	    /^#/ || NF < 2 { next; }
	    {
		# If it is already present and has a tag set,
		# then believe it.
		if (!match($2, /;default_tag=/))
			next;
		sub(/name=string,/, "", $2);
		sub(/;.*/, "", $2);
		for (i = 1; i <= nusingpvid; i++) {
			if (usingpvid[i] == $2)
				usingpvid[i]="";
		}
	    }
	    END {
		for (i = 1; i <= nusingpvid; i++) {
			if (usingpvid[i] != "") {
				printf("Warning: default VLAN tag set to 0" \
				    " on %s\n", usingpvid[i]);
				cmd=sprintf("dladm set-linkprop -p " \
				    "default_tag=0 %s\n", usingpvid[i]);
				system(cmd);
			}
		}
	    }'
}

#
# service_exists fmri
#
# returns success (0) if the service exists, 1 otherwise.
#
service_exists()
{
	/usr/sbin/svccfg -s $1 listpg > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		return 0;
	fi
	return 1;
}

#
# service_is_enabled fmri
#
# returns success (0) if the service is enabled (permanently or
# temporarily), 1 otherwise.
#
service_is_enabled()
{
	#
	# The -c option must be specified to use the composed view
	# because the general/enabled property takes immediate effect.
	# See Example 2 in svcprop(1).
	#
	# Look at the general_ovr/enabled (if it is present) first to
	# determine the temporarily enabled state.
	#
	tstate=`/usr/bin/svcprop -c -p general_ovr/enabled $1 2>/dev/null`
	if [ $? -eq 0 ]; then
		[ "$tstate" = "true" ] && return 0
		return 1
	fi

        state=`/usr/bin/svcprop -c -p general/enabled $1 2>/dev/null`
	[ "$state" = "true" ] && return 0
	return 1
}

#
# is_valid_v4addr addr
#
# Returns 0 if a valid IPv4 address is given, 1 otherwise.
#
is_valid_v4addr()
{ 
	echo $1 | /usr/xpg4/bin/awk 'NF != 1 { exit 1 } \
	$1 !~ /^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}\
	(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$/ \
	{ exit 1 }'
	return $?
}

#
# is_valid_v6addr addr
#
# Returns 0 if a valid IPv6 address is given, 1 otherwise.
#
is_valid_v6addr()
{
	echo $1 | /usr/xpg4/bin/awk 'NF != 1 { exit 1 } \
	# 1:2:3:4:5:6:7:8
	$1 !~ /^([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$/ &&
	# 1:2:3::6:7:8
	$1 !~ /^([a-fA-F0-9]{1,4}:){0,6}:([a-fA-F0-9]{1,4}:){0,6}\
	[a-fA-F0-9]{1,4}$/ && 
	# 1:2:3::
	$1 !~ /^([a-fA-F0-9]{1,4}:){0,7}:$/ &&
	# ::7:8
	$1 !~ /^:(:[a-fA-F0-9]{1,4}){0,6}:[a-fA-F0-9]{1,4}$/ && 
	# ::f:1.2.3.4
	$1 !~ /^:(:[a-fA-F0-9]{1,4}){0,5}:\
	((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}\
	(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$/ &&
	# a:b:c:d:e:f:1.2.3.4
	$1 !~ /^([a-fA-F0-9]{1,4}:){6}\
	((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}\
	(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$/ \
	{ exit 1 }'
	return $?
}

#
# is_valid_addr addr
#
# Returns 0 if a valid IPv4 or IPv6 address is given, 1 otherwise.
#
is_valid_addr()
{
	is_valid_v4addr $1 || is_valid_v6addr $1
}

#
# nwam_get_loc_prop location property
#
# echoes the value of the property for the given location
# return:
#	0 => property is set
#	1 => property is not set
#
nwam_get_loc_prop()
{
	value=`/usr/sbin/nwamcfg "select loc $1; get -V $2" 2>/dev/null`
	rtn=$?
	echo $value
	return $rtn
}

#
# nwam_get_loc_list_prop location property
#
# echoes a space-separated list of the property values for the given location
# return:
#	0 => property is set
#	1 => property is not set
#
nwam_get_loc_list_prop()
{
	clist=`/usr/sbin/nwamcfg "select loc $1; get -V $2" 2>/dev/null`
	rtn=$?
	#
	# nwamcfg gives us a comma-separated list;
	# need to convert commas to spaces.
	#
	slist=`echo $clist | sed -e s/","/" "/g`
	echo $slist
	return $rtn
}
