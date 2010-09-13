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
# Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T.
# All rights reserved.
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

# Run Commands executed when the system is changing to init state 3,
# same as state 2 (multi-user) but with remote file sharing.

PATH=/usr/sbin:/usr/bin

if [ -z "$SMF_RESTARTER" ]; then
	echo "This script cannot be run outside smf(5)."
	exit 1
fi

. /lib/svc/share/smf_include.sh

# Export boot parameters to rc scripts

set -- `/usr/bin/who -r`

_INIT_RUN_LEVEL="$7"	# Current run-level
_INIT_RUN_NPREV="$8"	# Number of times previously at current run-level
_INIT_PREV_LEVEL="$9"	# Previous run-level

set -- `/usr/bin/uname -a`

_INIT_UTS_SYSNAME="$1"  # Operating system name (uname -s)
_INIT_UTS_NODENAME="$2" # Node name (uname -n)
_INIT_UTS_RELEASE="$3"  # Operating system release (uname -r)
_INIT_UTS_VERSION="$4"  # Operating system version (uname -v)
_INIT_UTS_MACHINE="$5"  # Machine class (uname -m)
_INIT_UTS_ISA="$6"      # Instruction set architecture (uname -p)
_INIT_UTS_PLATFORM="$7" # Platform string (uname -i)

export _INIT_RUN_LEVEL _INIT_RUN_NPREV _INIT_PREV_LEVEL \
    _INIT_UTS_SYSNAME _INIT_UTS_NODENAME _INIT_UTS_RELEASE _INIT_UTS_VERSION \
    _INIT_UTS_MACHINE _INIT_UTS_ISA _INIT_UTS_PLATFORM

#
# Set _INIT_NET_STRATEGY and _INIT_NET_IF variables from /sbin/netstrategy
#
smf_netstrategy


if [ -d /etc/rc3.d ]; then
	for f in /etc/rc3.d/K*; do
		if [ -s $f ]; then
			case $f in
				*.sh)	/lib/svc/bin/lsvcrun -s $f stop ;;
				*)	/lib/svc/bin/lsvcrun $f stop ;;
			esac
		fi
	done

	for f in /etc/rc3.d/S*; do
		if [ -s $f ]; then
			case $f in
				*.sh)	/lib/svc/bin/lsvcrun -s $f start ;;
				*)	/lib/svc/bin/lsvcrun $f start ;;
			esac
		fi
	done
fi

if smf_is_globalzone; then
	# Unload all the loadable modules brought in during boot
	# Delay a few seconds to allow dtlogin to open console first.

	(sleep 5; modunload -i 0) & >/dev/null 2>&1
fi
