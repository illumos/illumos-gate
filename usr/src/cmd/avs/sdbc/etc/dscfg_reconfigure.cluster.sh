#!/usr/bin/ksh
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
# NWS DataServices within SunCluster reconfiguration script.
#
# Description:
#
# This script is called from /usr/cluster/lib/sc/run_reserve at
# appropriate times to start and stop the NWS DataServices as SunCluster
# disk device groups are brought online or taken offline.
#
# SNDR configuration requires that a resource group to be configured.
# 1. The resource group name should be same as device group name with -stor-rg
#    added. e.g. if device group name is abc-dg then resource group name
#    would be abc-dg-stor-rg. 
# 2. It should have 2 resources in it, unless one of the resource types is the
#    SUNW.GeoCtlAVS. One of type SUNW.LogicalHostname and either SUNW.HAStorage
#    or SUNW.HAStoragePlus types. Resource type versioning is ignored.
#    HAStorage type resource, should have ServicePaths property set to
#    device group name. HAStoragePlus type resource, should have either the
#    FilesystemMountPoints pointing to a files system associated with the
#    device group name, or GlobalDevicePaths property set to device group name.
#    LogicalHostname type resource should have a failoverIP address in it and
#    it will be used by SNDR to communicate with the secondary side.
#
# As SNDR requires that the LogicalHost (failover) IP address which is a
# part of resource group for SNDR, to be hosted on the same node where the 
# device group is, it tries to move the resource group also alongwith the
# device group, in become_primary case of run_reserve script. While
# in primary_to_secondary case, it will try to kill the switchover function
# if it is still running in background, after stopping NWS data services.
# 
# Usage:
#
# /usr/cluster/sbin/dscfg_reconfigure { start | stop } diskgroup
#
# Configuration:
#
# Scripts to be run should have been symlinked into $NWS_START_DIR and
# $NWS_STOP_DIR.  Note that the scripts are processed in lexical order,
# and that unlike /etc/rc?.d/ there is no leading S or K character.
#
# Exit status:
#
# 0 - success
# 1 - error
#

#
# Global variables
#

# this program
typeset -r ARGV0=$(basename $0)

# directory full of start scripts
typeset -r NWS_START_DIR=/usr/cluster/lib/dscfg/start

# directory full of stop scripts
typeset -r NWS_STOP_DIR=/usr/cluster/lib/dscfg/stop

# the syslog facility to use.
# - conceptually this should be based on the output of
#   "scha_cluster_get -O SYSLOG_FACILITY", but that won't work early
#   during boot.
typeset -r SYSLOG_FACILITY=daemon

PATH=$PATH:/usr/cluster/bin:/etc

# Variables for retrying scswitch of Resource group for SNDR
retry_num=12
retry_interval=10
rgname=
rgstat=
skip_resource=0
count_LogicalHostname=0
count_HAStoragePlus=0

# Since the switchover of the resource group is called in background,    
# the stop action of the reconfig script will kill the background switchover
# if it is running. Since we are stopping the NWS services on the node, there
# is no need to switch the resource group, so  it is killed.
# The pid of the process is kept in file /var/run/scnws/$dg.pid.
# Input:  dg - device group
# Output: Nothing, kills the process

function kill_scswitch
{
        dg=$1
        if [ -f /var/run/scnws/$dg.pid ]
        then
                for i in `cat /var/run/scnws/$dg.pid`
                do
                        pid=$i
                        kill -9 $pid
                done
                rm -f /var/run/scnws/$dg.pid
        fi
}

# Get the status of the resource group on this node, using scha commands.
# Input: resource group - $1
# Output: Status

function get_rgstat
{
	rg=$1
	rgstat=`scha_resourcegroup_get -O RG_STATE -G $rg`
}

# This function is called in background from do_scswitch function, to
# switch the resource group to this node, which is becoming primary for
# the diskgroup. If the status of resource group is Offline, it will use
# scswitch command to switch the resource group to this node. If it has
# become Online, cleanup pid file. If it is Pending, the resource group
# is in the state of becoming online, so wait for sometime to become Online..
# scswitch may fail, so the function retries $retry_num times, waiting for
# $retry_interval seconds.
# Input: resource group - $1, Diskgroup/Diskset - $2
# Output: 0 - success, 1 - failure

function switchfunc
{
        rg=$1
        dg=$2
	how_many=0
	sleep 2
	while [ $how_many != $retry_num ]
	do
		get_rgstat $rg
		case "$rgstat" in
		"ONLINE")
		 	rm -f /var/run/scnws/$dg.pid
			return 0
			;;

		"OFFLINE")
			logger -p ${SYSLOG_FACILITY}.notice \
			-t "NWS.[$ARGV0]" `gettext "scswitch of resource group"` "$rg"

			scswitch -z -g $rg -h $(hostname)
			retval=$?
			if [ $retval != 0 ]
			then
				sleep $retry_interval
				how_many=$(($how_many + 1))
			fi
			;;

		"PENDING_ONLINE")
			logger -p ${SYSLOG_FACILITY}.notice \
			-t "NWS.[$ARGV0]" `gettext "pending online of resource group"` "$rg"
			sleep $retry_interval
			how_many=$(($how_many + 1))
			;;

		*)
			logger -p ${SYSLOG_FACILITY}.notice \
			-t "NWS.[$ARGV0]" `gettext "Improper resource group status for Remote Mirror"` "$rgstat"
		 	rm -f /var/run/scnws/$dg.pid
			return 1
			;;	
		esac
	done
	logger -p ${SYSLOG_FACILITY}.err \
	-t "NWS.[$ARGV0]" "Did not switch resource group for Remote Mirror. System Administrator intervention required"
 	rm -f /var/run/scnws/$dg.pid
	return 1
}


# This function calls switchfunc function in background, to switch the 
# resource group for SNDR. It validates the diskgroup/diskset is configured 
# for SNDR, checks if the resource group is in Managed state etc.
# If it detects a mis-configuration, it will disable SNDR for the
# device group being processed. This is to prevent cluster hangs and panics.
#  
# The ServicePaths extension property of HAStorage type resource or the
# GlobalDevicePaths extension property of HAStoragePlus, both of which
# specify the device group, serve as a link or mapping to retrieve the 
# resource group associated with the SNDR configured device group.
# Switchfunc is called in the background to avoid the deadlock situation arising
# out of switchover of resource group from within device group switchover.
#
# In run_reserve context, we are doing the device group switchover, trying to
# bring it online on the node. Device group is not completely switched online,
# until the calling script run_reserve returns. In the process, we are calling
# the associated SNDR resource group switchover using scswitch command. 
# Resource group switchover will trigger the switchover of device group also. 
#
# If resource group switchover is called in foreground, before the device 
# group has become online, then it will result in switching the device group 
# again, resulting in deadlock. Resource group can not become online until 
# the device group is online and the device group can not become online until the 
# script returns, causing this circular dependency resulting in deadlock. 
#
# Calling the resource group switch in background allows current run_reserve
# script to return immediately, allowing device group to become online.
# If the device group is already online on the node, then the resource group 
# does not cause the device group switchover again.
#
# Input: Device group dg - $1
# Output: 0 - success
#	  1 - either dg not applicable for SNDR or error
#	  2 - SNDR mis-configuration

function do_scswitch
{
	dg=$1

        if [ ! -x /usr/cluster/bin/scha_resource_get \
		-o ! -x /usr/cluster/bin/scha_resourcegroup_get ]
        then
                return 1
        fi

# hard coded rg name from dg
	rgname="$dg-stor-rg"
	scha_resourcegroup_get -O rg_description -G $rgname > /dev/null
	if [ $? != 0 ]
	then
# There is no device group configured in cluster for SNDR with this cluster tag
		return 1
	fi

# Check the state of resource group

	get_rgstat $rgname
	if [ -z "$rgstat" \
		-o "$rgstat" = "UNMANAGED" -o "$rgstat" = "ERROR_STOP_FAILED" ]
	then
		logger -p ${SYSLOG_FACILITY}.notice \
		-t "NWS.[$ARGV0]" \
		`gettext "Improper Remote Mirror resource group state"` "$rgstat"
        	return 2 
	fi

# Check whether resources are of proper type and they are enabled

	rs_list=`scha_resourcegroup_get -O resource_list -G $rgname`
	if [ -z "$rs_list" ]
	then
		logger -p ${SYSLOG_FACILITY}.notice \
		-t "NWS.[$ARGV0]" \
		`gettext "No resources in Remote Mirror resource group <$rgname>"`
		return 2 
	fi
	for rs in $rs_list
	do
		rs_type=`scha_resource_get -O type -R $rs -G $rgname  | cut -d':' -f1`
		case "$rs_type" in
		SUNW.LogicalHostname)
			rs_enb=`scha_resource_get -O ON_OFF_SWITCH -R $rs -G $rgname`
			if [ "$rs_enb" = "ENABLED" ]
			then
			count_LogicalHostname=$(($count_LogicalHostname + 1))
			fi
			;;
		SUNW.HAStoragePlus)
			rs_enb=`scha_resource_get -O ON_OFF_SWITCH -R $rs -G $rgname`
			if [ "$rs_enb" = "ENABLED" ]
			then
			count_HAStoragePlus=$(($count_HAStoragePlus + 1))
			fi
			;;
		esac
	done
	if [ $count_LogicalHostname -lt 1 ]
	then
		logger -p ${SYSLOG_FACILITY}.notice \
		-t "NWS.[$ARGV0]" `gettext "Missing Enabled Logical Host in resource group <$rgname> for Remote Mirror"`
		return 2
	elif [ $count_LogicalHostname -gt 1 ]
        then
		logger -p ${SYSLOG_FACILITY}.notice \
		-t "NWS.[$ARGV0]" `gettext "Too Many Enabled Logical Host in resource group <$rgname> for Remote Mirror"`
		return 2
	fi

	if [ $count_HAStoragePlus -lt 1 ]
	then
		logger -p ${SYSLOG_FACILITY}.notice \
		-t "NWS.[$ARGV0]" `gettext "Missing Enabled HAStoragePlus in resource group <$rgname> for Remote Mirror"`
		return 2
	elif [ $count_HAStoragePlus -gt 1 ]
	then
		logger -p ${SYSLOG_FACILITY}.notice \
		-t "NWS.[$ARGV0]" `gettext "Too Many Enabled HAStoragePlus in resource group <$rgname> for Remote Mirror"`
		return 2
	fi

# Invoke switchfunc to switch the resource group. 

	switchfunc $rgname $dg &
	pid=$!
	mkdir -p /var/run/scnws/
	rm -f /var/run/scnws/$dg.pid
	echo $pid > /var/run/scnws/$dg.pid

	return 0
}


#
# Functions
#

usage()
{
	logger -p ${SYSLOG_FACILITY}.err \
	    -t "NWS.[$ARGV0]" "usage: $ARGV0 { start | stop } diskgroup"
	exit 1
}


# Input: arg1) $NWS_START_DIR - location of NWS scripts
#	 arg2) start / stop
#	 arg3 ) device group - $2
#	 arg4) sndr_ena / sndr_dis
# Output: Nothing. Log error if seen

process_dir()
{
	typeset dir=$1
	typeset arg1=$2
	typeset dg=$3
	typeset arg2=$4
	typeset RDC=$dir/10rdc

	if [[ -d $dir ]]
	then
		for f in $dir/*
		do
			# process scripts in the directories in lexical order
			# note - no leading S or K unlike /etc/rc?.d/

			if [ -s $f ] && [ $arg2 != "sndr_dis" ]   
			then
				# run script and pipe output through
				# logger into syslog

				/usr/bin/ksh $f $arg1 $dg 2>&1 |
				    logger -p ${SYSLOG_FACILITY}.notice \
					-t "NWS.[${ARGV0}:$(basename $f)]"
			else
			# SNDR misconfigured - prevent start
                            if [ -s $f ] && [ $f != $RDC ] 
                            then
                                # run script and pipe output through
                                # logger into syslog
                                /usr/bin/ksh $f $arg1 $dg 2>&1 |
                                    logger -p ${SYSLOG_FACILITY}.notice \
                                        -t "NWS.[${ARGV0}:$(basename $f)]"
			    fi
			fi
		done
	else
		logger -p ${SYSLOG_FACILITY}.err \
		    -t "NWS.[$ARGV0]" "no directory: $dir"
	fi
}


#
# main
#

if [ $# -ne 2 ]
then
	usage
	# not reached
fi


case "$1" in
start)
	logger -p ${SYSLOG_FACILITY}.notice -t "NWS.[$ARGV0]" "starting: $ARGV0 $*"
	do_scswitch $2
	retval=$?
	if [ $retval == 2 ]
	then
		logger -p ${SYSLOG_FACILITY}.err \
		    -t "NWS.[$ARGV0]" "**FATAL ERROR** Remote Mirror is mis-configured and DISABLED for devicegroup <"$2"> " 
		# Disable SNDR 
		process_dir $NWS_START_DIR start "$2" sndr_dis
	else
		process_dir $NWS_START_DIR start "$2" sndr_ena
	fi
	;;
stop)
	logger -p ${SYSLOG_FACILITY}.notice -t "NWS.[$ARGV0]" "stopping: $ARGV0 $*"
	process_dir $NWS_STOP_DIR stop "$2" sndr_ena
	kill_scswitch $2
	;;

*)
	usage
	# not reached
	;;
esac

logger -p ${SYSLOG_FACILITY}.notice -t "NWS.[$ARGV0]" "completed: $ARGV0 $*"

exit 0
