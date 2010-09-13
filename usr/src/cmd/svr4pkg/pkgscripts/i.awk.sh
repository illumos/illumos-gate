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
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

error=no
while read src dest
do
	[ "$src" = /dev/null ] && continue

	echo "Modifying $dest"

	# Strip PKG_INSTALL_ROOT from dest if installation is to an
	# alternate root.

	if [ -n "$PKG_INSTALL_ROOT" -a "$PKG_INSTALL_ROOT" != "/" ]; then
		client_dest=`echo $dest | \
			/usr/bin/nawk -v rootdir="$PKG_INSTALL_ROOT" '{
				{ print substr($0, length(rootdir)+1)} }'`
		savepath=$PKGSAV/awk${client_dest}
	else
		savepath=$PKGSAV/awk${dest}
	fi

	dirname=`dirname $savepath`
	if [ $? -ne 0 ]
	then
		error=yes
		continue
	fi
	if [ ! -d $dirname ]
	then
		# ignore return code since mkdir has bug
		mkdir -p $dirname
	fi

	cp $src $savepath &&
	/usr/sadm/install/scripts/cmdexec /usr/bin/awk install $savepath $dest

	if [ $? -ne 0 ]
	then
		error=yes
		continue
	fi
done
[ "$error" = yes ] &&
	exit 2
exit 0
