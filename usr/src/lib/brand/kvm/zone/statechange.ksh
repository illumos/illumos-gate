#!/bin/ksh -p
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
# Copyright 2012 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

. /lib/sdc/config.sh

# subcommand:
# pre
# post

# state
# ZONE_STATE_CONFIGURED		0 (script will never see this)
# ZONE_STATE_INCOMPLETE		1 (script will never see this)
# ZONE_STATE_INSTALLED		2
# ZONE_STATE_READY		3
# ZONE_STATE_RUNNING		4
# ZONE_STATE_SHUTTING_DOWN	5
# ZONE_STATE_DOWN		6
# ZONE_STATE_MOUNTED		7

# cmd
#
# ready				0
# boot				1
# forceboot			2
# reboot			3
# halt				4
# uninstalling			5
# mount				6
# forcemount			7
# unmount			8

subcommand=$1
ZONENAME=$2
ZONEPATH=$3
state=$4
cmd=$5

LOCKFILE=/etc/dladm/zone.lck
KVMLOG=/tmp/kvm.log=

#
# Create a lock file which we use to serialize datalink operations across zones.
#
lock_file()
{
	while true; do
		if (set -o noclobber; echo "$$" >$LOCKFILE) 2>/dev/null; then
			trap 'rm -f $LOCKFILE; exit $?' INT TERM EXIT
			break;
		else
			sleep 1
		fi
	done
}

unlock_file()
{
	rm -f $LOCKFILE
	trap - INT TERM EXIT
}

#
# Set up the vnic(s) for the zone.
#
setup_net()
{
	# XXX old code, is this still needed by anything?
	# touch $ZONEPATH/netsetup

	for nic in $_ZONECFG_net_resources
	do
		# Get simplified versions of the network config. variables.
		address=$(eval echo \$_ZONECFG_net_${nic}_address)
        dhcp_server=$(eval echo \$_ZONECFG_net_${nic}_dhcp_server)
		global_nic=$(eval echo \$_ZONECFG_net_${nic}_global_nic)
		mac_addr=$(eval echo \$_ZONECFG_net_${nic}_mac_addr)
		vlan_id=$(eval echo \$_ZONECFG_net_${nic}_vlan_id)
		blocked_outgoing_ports=$(eval \
		    echo \$_ZONECFG_net_${nic}_blocked_outgoing_ports)
		zone_ip=$(eval echo \$_ZONECFG_net_${nic}_ip)
		allow_ip_spoof=$(eval \
		    echo \$_ZONECFG_net_${nic}_allow_ip_spoofing)
		allow_mac_spoof=$(eval \
		    echo \$_ZONECFG_net_${nic}_allow_mac_spoofing)
		allow_restricted_traffic=$(eval \
		    echo \$_ZONECFG_net_${nic}_allow_restricted_traffic)

		# If address set, must be a shared stack zone
		[[ -n $address ]] && exit 0

		# If no global-nic, must be a dedicated physical NIC instead
		# of a vnic
		[[ -z $global_nic ]] && continue

		orig_global=$global_nic
		global_nic=$(eval echo \$SYSINFO_NIC_${orig_global})

		# If the global nic is specified as a device or etherstub name
		# rather than a tag
		if [[ -z $global_nic ]]; then
			echo "$(dladm show-phys -p -o LINK) $(dladm show-etherstub -p -o LINK)" \
			  | egrep "(^| )${orig_global}( |$)" > /dev/null
			(( $? == 0 )) && global_nic=${orig_global}
		fi

		# For backwards compatibility with the other parts of the
		# system, check if this zone already has this vnic setup.
		# If so, move on to the next vnic.
		dladm show-vnic -p -o LINK -z $ZONENAME $nic >/dev/null 2>&1
		(( $? == 0 )) && continue

		if [[ -z $global_nic ]]; then
			echo "undefined VNIC $nic " \
			    "(global NIC $orig_global)"
			logger -p daemon.err "zone $ZONENAME " \
			    "undefined VNIC $nic (global NIC $orig_global)"
			exit 1
		fi

		lock_file

		#
		# Create the vnic.
		#

		opt_str="-p zone=$ZONENAME"
		[[ -n $mac_addr ]] && opt_str="$opt_str -m $mac_addr"

		[[ -n $vlan_id && $vlan_id != 0 ]] && \
		    opt_str="$opt_str -v $vlan_id"

		#
		# Creating a VNIC in a zone is a multi-step process internally.
		# This means there is a short window where the VNIC exists in
		# the global zone and that could lead to a race condition if
		# two zones boot at the same time with the same VNIC name.  Use
		# a temp. name to create the VNIC then rename it to have the
		# correct name.
		#
		tname=tmp$$0
		dout=`dladm create-vnic -t -l $global_nic $opt_str $tname 2>&1`
		if (( $? != 0 )); then
			print -f "error creating VNIC %s (global NIC %s)\n" \
			   "$nic" "$orig_global"
			print -f "msg: %s\n" "$dout"
			logger -p daemon.err "zone $ZONENAME error creating " \
			    "VNIC $nic (global NIC $orig_global $global_nic)"
			logger -p daemon.err "msg: $dout"
			logger -p daemon.err "Failed cmd: dladm create-vnic " \
			    "-t -l $global_nic $opt_str $tname"

			# Show more info if dup MAC addr.
			echo $dout | egrep -s "MAC address is already in use"
			if (( $? == 0 )); then
				entry=`dladm show-vnic -olink,macaddress,zone \
				    | nawk -v addr=$mac_addr '{
					if ($2 == addr)
						print $0
				    }'`
				if [[ -n $entry ]]; then
					print -f "LINK\tMACADDRESS\tZONE\n"
					print -f "%s\n" "$entry"
				fi
			fi
			exit 1
		fi
		dladm rename-link -z $ZONENAME $tname $nic
		if (( $? != 0 )); then
			echo "error renaming VNIC $tname $nic"
			logger -p daemon.err "zone $ZONENAME error renaming " \
			    "VNIC $tname $nic"
			exit 1
		fi

		if [[ -z $mac_addr ]]; then
			# There was no assigned mac address

			# Get newly assigned mac address.
			mac_addr=$(dladm show-vnic -z $ZONENAME -p -o \
			    MACADDRESS ${nic})

			# Save newly assigned mac address
			[[ -n $mac_addr ]] && zonecfg -z $ZONENAME \
			    "select net physical=$nic; " \
			    "set mac-addr=$mac_addr; end; exit"
		fi

		# Set up antispoof options

		if [[ $dhcp_server == "1" ]] || [[ $dhcp_server == "true" ]]; then
			enable_dhcp="true"
			# This needs to be off for dhcp server zones
			allow_ip_spoof=1
		fi

		comma=""
		spoof_opts=""
		if [[ $allow_mac_spoof != "1" ]]; then
			spoof_opts="${spoof_opts}${comma}mac-nospoof"
			comma=","
		fi
		if [[ $allow_ip_spoof != "1" ]]; then
			spoof_opts="${spoof_opts}${comma}ip-nospoof"
			comma=","
		fi
		if [[ $allow_restricted_traffic != "1" ]]; then
			spoof_opts="${spoof_opts}${comma}restricted"
			comma=","
		fi
		if [[ -z "${enable_dhcp}" ]]; then
			spoof_opts="${spoof_opts}${comma}dhcp-nospoof"
			comma=","
		fi

		if [[ -n ${spoof_opts} ]]; then
			dladm set-linkprop -t -z $ZONENAME -p \
			"protection=${spoof_opts}" ${nic}
			if (( $? != 0 )); then
				echo "error setting VNIC protection $nic $spoof_opts"
				    logger -p daemon.err "zone $ZONENAME error setting " \
				    "VNIC protection $nic $spoof_opts"
			exit 1
			fi
		fi

		if [[ -n "${zone_ip}" ]] && [[ $allow_ip_spoof != "1" ]] && \
			    [[ "${zone_ip}" != "dhcp" ]]; then
			dladm set-linkprop -t -z $ZONENAME \
			    -p "allowed-ips=${zone_ip}" ${nic}
			if (( $? != 0 )); then
				echo "error setting VNIC allowed-ip " \
				    "$nic $zone_ip"
				logger -p daemon.err "zone $ZONENAME " \
				    "error setting VNIC allowed-ip " \
				    "$nic $zone_ip"
				exit 1
			fi
		fi

		# If on VMWare and we have external IPs, create a bridge to
		# allow zones to reach the external gateway
		if [[ ${orig_global} == "external" && \
		    "${SYSINFO_Product}" == "VMware Virtual Platform" ]]; then
			dladm show-bridge -p -o BRIDGE vmwareextbr \
			    >/dev/null 2>&1
			if (( $? != 0 )); then
				dladm create-bridge -l ${SYSINFO_NIC_external} \
				    vmwareextbr
				if (( $? != 0 )); then
					echo "error creating bridge vmwareextbr"
					logger -p daemon.err "error creating " \
					    "bridge vmwareextbr"
					exit 1
				fi
			fi
		fi

		if [[ -n $blocked_outgoing_ports ]]; then
			OLDIFS=$IFS
			IFS=,
			for port in $blocked_outgoing_ports; do
				# br='block remote'.  Flow names should be < 31
				# chars in length so that they get unique
				# kstats.
			 	# Use the VNIC mac addr. to generate a unique
				# name.
				mac_addr=`dladm show-vnic -z $ZONENAME -p \
				    -o MACADDRESS $nic | tr ':' '_'`
				flowadm add-flow -t -l $nic -z $ZONENAME \
				    -a transport=tcp,remote_port=$port \
				    -p maxbw=0 f${mac_addr}_br_${port}
				if (( $? != 0 )); then
					echo "error adding flow " \
					    "$nic f${mac_addr}_br_${port}"
					logger -p daemon.err "zone $ZONENAME " \
					    "error adding flow " \
					    "$nic f${mac_addr}_br_${port}"
					exit 1
				fi
			done
			IFS=$OLDIFS
		fi

		unlock_file
	done
}

#
# We're readying the zone.  Make sure the per-zone writable
# directories exist so that we can lofs mount them.  We do this here,
# instead of in the install script, since this list has evolved and
# there are already zones out there in the installed state.
#
setup_fs()
{
	uname -v > $ZONEPATH/lastbooted
}

#
# If the zone has a CPU cap, calculate the CPU baseline and set it so we can
# track when we're bursting.  There are many ways that the baseline can be
# calculated based on the other settings in the zones (e.g. a simple way would
# be as a precentage of the cap).
#
# For SmartMachines, our CPU baseline is calculated off of the system's
# provisionable memory and the memory cap of the zone. We assume that 83% of
# the system's memory is usable by zones (the rest is for the OS) and we assume
# that the zone memory cap is set so that we're proportional to how many zones
# we can provision on the system (i.e. we don't overprovision memory).  Using
# these assumptions, we calculate the proportion of CPU for the zone based on
# its proportion of memory. Thus, the zone's CPU baseline is calculated using:
#     ((zone capped memsize in MB) * 100) / (MB/core).
# Uncapped zones have no baseline (i.e. infrastructure zones).
#
# Remember that the cpu-cap rctl and the baseline are expressed in units of
# a percent of a CPU, so 100 is 1 full CPU.
#
setup_cpu_baseline()
{
	# If there is already a baseline, don't set one heuristically
	curr_base=`prctl -P -n zone.cpu-baseline -i zone $ZONENAME | nawk '{
		if ($2 == "privileged") print $3
	    }'`
	[ -n "$curr_base" ] && return

	# Get current cap and convert from zonecfg format into rctl format
	cap=`zonecfg -z $ZONENAME info capped-cpu | nawk '{
	    if ($1 == "[ncpus:") print (substr($2, 1, length($2) - 1) * 100)
	}'`
	[ -z "$cap" ] && return

	# Get zone's memory cap in MB times 100
	zmem=`zonecfg -z $ZONENAME info capped-memory | nawk '{
	    if ($1 == "[physical:") {
	        val = substr($2, 1, length($2) - 2)
	        units = substr($2, length($2) - 1, 1)

	        # convert GB to MB
	        if (units == "G")
	            val *= 1024
	        print (val * 100)
	    }
	}'`
	[ -z "$zmem" ] && return

	# Get system's total memory in MB
	smem=`prtconf -m`
	# provisionable memory is 83% of total memory (bash can't do floats)
	prov_mem=$((($smem * 83) / 100))
	nprocs=`psrinfo -v | \
	    nawk '/virtual processor/ {cnt++} END {print cnt}'`

	mb_per_core=$(($prov_mem / $nprocs))

	baseline=$(($zmem / $mb_per_core))
	[[ $baseline == 0 ]] && baseline=1
	[[ $baseline -gt $cap ]] && baseline=$cap

	prctl -n zone.cpu-baseline -v $baseline -t priv -i zone $ZONENAME
}

#
# We're halting the zone, perform network cleanup.
#
cleanup_net()
{
	# Cleanup any flows that were setup.
	for nic in $_ZONECFG_net_resources
	do
		lock_file

		flowadm remove-flow -t -z $ZONENAME -l $nic
		if (( $? != 0 )); then
			echo "error removing flows for $nic"
			logger -p daemon.err "zone $ZONENAME " \
			    "error removing flows for $nic"
		fi

		unlock_file
	done
}

kill_gz_sockholder()
{
	echo "searching for GZ process holding socket $1"
	logger -p daemon.err "zone $ZONENAME " \
	    "searching for GZ process holding socket $1"

	pid=`(cd /proc;
	for i in *;
	do
		pfiles $i 2>/dev/null | egrep -s "AF_UNIX $1";
		[ $? == 0 ] && echo "$i";
	done)`

	[ -z "$pid" ] && return

	echo "killing GZ process $pid holding socket $1"
	logger -p daemon.err "zone $ZONENAME " \
	    "killing GZ process $pid holding socket $1"

	kill -9 $pid
}

# zonadmd unable to unmount the given path, try to cleanup so unmount can
# succeed.
cleanup_mount()
{
	echo "attempting to cleanup mount $1"
	logger -p daemon.err "zone $ZONENAME " \
	    "attempting to cleanup mount $1"

	cnt=`fuser -c $1 2>/dev/null | wc -w`
	if [ $cnt -gt 0 ]; then
		echo "trying to kill GZ processes under $1"
		logger -p daemon.err "zone $ZONENAME " \
		    "trying to kill GZ processes under $1"
		fuser -ck $1

		# Exit out to give the zoneadmd umount a chance to suceed now.
		# Zoneadmd will give us another shot if it still can't umount.
		sleep 1
		exit 0
	fi

	# Processes which are injected into a zone and then open a file as a
	# socket end-point will show in pfiles with the path relative to the
	# zone's root. For example, a zone with its root at /zones/foo/root and
	# an open socket as /zones/foo/root/var/run/x will show up in a pfiles
	# search as /var/run/x. This is a problem since we have no way to
	# narrow down which process to kill.
	#
	# Because the socket doesn't have enough information for us to tie to
	# the specific GZ process, we hardcode to kill things we know will open
	# sockets into the zone:
	#    /var/run/smartdc/metadata.sock
	#    /var/run/.smartdc-amon.sock

	ZVR=$ZONEPATH/root/var/run
	[ -S $ZVR/smartdc/metadata.sock ] &&
	    kill_gz_sockholder /var/run/smartdc/metadata.sock

	[ -S $ZVR/.smartdc-amon.sock ] &&
	    kill_gz_sockholder /var/run/.smartdc-amon.sock
}

#
# Main
#

# Load sysinfo variables with SYSINFO_ prefix
load_sdc_sysinfo
# Load config variables with CONFIG_ prefix, and sets the headnode variable
load_sdc_config

echo "statechange $subcommand $cmd" >>/tmp/kvm.log
[[ "$subcommand" == "pre" && $cmd == 0 ]] && setup_fs
[[ "$subcommand" == "pre" && $cmd == 4 ]] && cleanup_net
[[ "$subcommand" == "post" && $cmd == 0 ]] && setup_net
# We can't set a rctl until we have a process in the zone to grab
[[ "$subcommand" == "post" && $cmd == 1 ]] && setup_cpu_baseline

# Zone halt is hung unmounting, try to recover
[[ "$subcommand" == "post" && $state == 6 && $cmd == 8 ]] && \
    cleanup_mount "$6"

exit 0
