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
while read dest
do
	if [ -d $dest ]
	then
		echo "$dest"
		rmdir $dest || error=yes
	elif [ -f $dest ]
	then
		echo "Modifying $dest"

		# Strip PKG_INSTALL_ROOT from dest if installation is to an
		# alternate root.

		if [ -n "$PKG_INSTALL_ROOT" -a "$PKG_INSTALL_ROOT" != "/" ]; then
			client_dest=`echo $dest | \
				/usr/bin/nawk -v rootdir="$PKG_INSTALL_ROOT" '{
				    { print substr($0, length(rootdir)+1)} }'`
			savepath=$PKGSAV/build${client_dest}
		else
			savepath=$PKGSAV/build${dest}
		fi

		chmod +x $savepath
		if $savepath remove > /tmp/$$build
		then
			if [ ! -s /tmp/$$build ]
			then
				rm -f $dest
			else
				cp /tmp/$$build $dest || error=yes
			fi
		else
			error=yes
		fi
		rm -f /tmp/$$build
	else
		[ -r $dest ] && echo "$dest"
		rm -f $dest || error=yes
	fi
done
[ "$error" = yes ] &&
	exit 2
exit 0
