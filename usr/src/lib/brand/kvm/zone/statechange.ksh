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
# Copyright 2010, 2011 Joyent, Inc.  All rights reserved.
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
# halt				4

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
	touch $ZONEPATH/netsetup
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

exit 0
