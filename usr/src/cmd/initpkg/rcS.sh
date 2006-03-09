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
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T.
# All rights reserved.
#
#

# This file executes the commands in the rcS.d directory, which are necessary
# to get the system to single user mode:
#
# 	establish minimal network plumbing (for diskless and dataless)
#	mount /usr (if a separate file system)
#	set the system name
#	check the root (/) and /usr file systems
#	check and mount /var and /var/adm (if a separate file system)
#	mount pseudo file systems (/dev/fd)
#	if this is a reconfiguration boot, [re]build the device entries
#	check and mount other file systems to be mounted in single user mode

if [ -z "$SMF_RESTARTER" ]; then
	echo "Cannot be run outside smf(5)"
	exit 1
fi

. /lib/svc/share/smf_include.sh

#
# Default definitions:
#
PATH=/usr/sbin:/usr/bin:/sbin
vfstab=/etc/vfstab
mnttab=/etc/mnttab
mntlist=
option=
otherops=

action=$1

# Export boot parameters to rc scripts

if [ "x$1" != xsysinit -a -d /usr/bin ]; then
	set -- `/usr/bin/who -r`

	_INIT_RUN_LEVEL=${7:-S}   # Current run-level
	_INIT_RUN_NPREV=${8:-0}   # Number of times previously at current level
	_INIT_PREV_LEVEL=${9:-0}  # Previous run-level
else
	_INIT_RUN_LEVEL=S
	_INIT_RUN_NPREV=0
	_INIT_PREV_LEVEL=0
fi

set -- `/sbin/uname -a`

#
# If we're booting, uname -a will produce one fewer token than usual because
# the hostname has not yet been configured.  Leave NODENAME empty in this case.
#
if [ $# -eq 7 ]; then
	_INIT_UTS_SYSNAME="$1"  # Operating system name (uname -s)
	_INIT_UTS_NODENAME="$2" # Node name (uname -n)
	shift 2
else
	_INIT_UTS_SYSNAME="$1"  # Operating system name (uname -s)
	_INIT_UTS_NODENAME=	# Node name is not yet configured
	shift 1
fi

_INIT_UTS_RELEASE="$1"  # Operating system release (uname -r)
_INIT_UTS_VERSION="$2"  # Operating system version (uname -v)
_INIT_UTS_MACHINE="$3"  # Machine class (uname -m)
_INIT_UTS_ISA="$4"      # Instruction set architecture (uname -p)
_INIT_UTS_PLATFORM="$5" # Platform string (uname -i)

export _INIT_RUN_LEVEL _INIT_RUN_NPREV _INIT_PREV_LEVEL \
    _INIT_UTS_SYSNAME _INIT_UTS_NODENAME _INIT_UTS_RELEASE _INIT_UTS_VERSION \
    _INIT_UTS_MACHINE _INIT_UTS_ISA _INIT_UTS_PLATFORM

#
# Set _INIT_NET_STRATEGY and _INIT_NET_IF variables from /sbin/netstrategy
#
smf_netstrategy

. /lib/svc/share/fs_include.sh

#
# Make the old, deprecated environment variable (_DVFS_RECONFIG) and the new
# supported environment variable (_INIT_RECONFIG) to be synonyms.  Set both
# if the svc.startd reconfigure property is set.  Note that for complete
# backwards compatibility the value "YES" is significant with _DVFS_RECONFIG.
# The # value associated with _INIT_RECONFIG is insignificant.  What is
# significant is only that the environment variable is defined.
#

svcprop -q -p system/reconfigure system/svc/restarter:default
if [ $? -eq 0 ]
then
	echo "Setting _INIT_RECONFIG."
	_DVFS_RECONFIG=YES; export _DVFS_RECONFIG
	_INIT_RECONFIG=set; export _INIT_RECONFIG
fi


case $action in
	stop)
		>/etc/nologin

		# All remote filesystem services must be explicitly disabled
		# at the single-user milestone.  There's no need to unmount
		# remote filesystems here.

		if [ -d /etc/rcS.d ]; then
			for f in /etc/rcS.d/K*; do
				if [ ! -s $f ]; then
					continue
				fi

				case $f in
					*.sh)	/lib/svc/bin/lsvcrun -s $f stop
						;;
					*)	/lib/svc/bin/lsvcrun $f stop ;;
				esac
			done
		fi

		;;

	start)
		if [ -d /etc/rcS.d ]; then
			for f in /etc/rcS.d/S*; do
				if [ ! -s $f ]; then
					continue
				fi

				case $f in
					*.sh)	/lib/svc/bin/lsvcrun -s $f start
						;;
					*)	/lib/svc/bin/lsvcrun $f start ;;
				esac
			done
		fi

		#
		# Clean up the /reconfigure file and sync the new entries to
		# stable media.
		#

		# GLXXX - svc.startd should do this?
		if [ -n "$_INIT_RECONFIG" ]; then
			[ -f /reconfigure  ] && /usr/bin/rm -f /reconfigure
			/sbin/sync
		fi
		;;

	*)
		echo "Usage: $0 { start | stop }"
		exit $SMF_EXIT_ERR_CONFIG
		;;
esac

exit $SMF_EXIT_OK
