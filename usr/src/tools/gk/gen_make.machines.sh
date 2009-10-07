#!/usr/bin/ksh93
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
# script to generate example .make.machines for build users
#


PATH=/usr/bin:/usr/sbin

THISHOST=$(uname -n)

cpus=$(psrinfo | grep on-line | wc -l)
max=$(((cpus + 1) * 2))

EXISTING=$(grep "^$THISHOST" $HOME/.make.machines |awk -F"=" '{print $2}')

if [[ -n "$EXISTING" ]] then
	printf "Your existing \$HOME/.make.machines has a concurrency "
	printf "setting of $EXISTING for host\n"
	printf "$THISHOST. If you wish to change the setting then this "
	printf "script suggests\nsetting concurrency to $max for a single-user "
	printf "machine. Multi-user machines might\nrequire different values.\n"
else
	printf "$THISHOST max=$max\n" >> $HOME/.make.machines
	printf "dmake concurrency for host $THISHOST set to $max.\n"
fi
