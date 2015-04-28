#!/bin/ksh -p
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright 2015 Joyent, Inc.  All rights reserved.
#

PATH=/bin:/usr/bin:/usr/sbin:/usr/sfw/bin
export PATH

# If we weren't passed 3 arguments, exit now.
[[ $# -lt 3 ]] && usage

# Extract the brand directory name from the path.
branddir=$(dirname "$0")
zonename="$1"
zoneroot="$2"
install_src="3"
install_root="$zoneroot/root"

if [[ ! -f "$install_src" ]]; then
	echo "$install_src: file not found\n"
	exit 254
fi

if [[ ! -d "$install_root" ]]; then
	if ! mkdir -p "$install_root" 2>/dev/null; then
		echo "Could not create install directory $install_root"
		exit 254
	fi
fi

if ! ( cd "$install_root" && gtar -xzf "$install_src" ) ; then
	echo "Error: extraction from tar archive failed"
	exit 255
fi

$branddir/lx_init_zone "$zonename" "$install_root"
if [[ $? -ne 0 ]]; then
	echo "Install failed"
	exit 255
fi

exit 0
