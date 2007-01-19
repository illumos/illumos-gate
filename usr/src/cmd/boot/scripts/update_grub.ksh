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

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# ident	"%Z%%M%	%I%	%E% SMI"

PATH="/usr/bin:/usr/sbin:${PATH}"; export PATH
ALT_ROOT=

while getopts R: OPT 2>/dev/null
do
	case $OPT in
	R)	ALT_ROOT="$OPTARG"
		;;
	?)	echo "Usage: ${0##*/}: [-R \<root\>]"
		;;
	esac
done

ARCH=`uname -p`

is_pcfs_boot=yes

check_pcfs_boot()
{
	bootdev=`grep -v "^#" "$ALT_ROOT"/etc/vfstab | grep pcfs \
	    | grep "[       ]/stubboot[      ]" | nawk '{print $1}'`
	if [ X"$bootdev" = "X" ]; then
		is_pcfs_boot=no
	fi
}

#
# Detect SVM root and return the list of raw devices under the mirror
#
get_rootdev_list()
{
	if [ -f "$ALT_ROOT"/etc/lu/GRUB_slice ]; then
		grep '^PHYS_SLICE' "$ALT_ROOT"/etc/lu/GRUB_slice | cut -d= -f2
	else
		metadev=`grep -v "^#" "$ALT_ROOT"/etc/vfstab | \
		    grep "[	 ]/[ 	]" | nawk '{print $2}'`
		if [[ $metadev = /dev/rdsk/* ]]; then
			rootdevlist=`echo "$metadev" | sed -e "s#/dev/rdsk/##"`
		elif [[ $metadev = /dev/md/rdsk/* ]]; then
			metavol=`echo "$metadev" | sed -e "s#/dev/md/rdsk/##"`
			rootdevlist=`metastat -p $metavol |\
			    grep -v "^$metavol[	 ]" | nawk '{print $4}'`
		fi
		for rootdev in $rootdevlist
		do
			echo /dev/rdsk/$rootdev
		done
	fi
}

#
# multiboot: install grub on the boot slice
#
install_grub()
{
	# Stage 2 blocks must remain untouched
	STAGE1="$ALT_ROOT"/boot/grub/stage1
	STAGE2="$ALT_ROOT"/boot/grub/stage2

	if [ $is_pcfs_boot = yes ]; then
		#
		# Note: /stubboot/boot/grub/stage2 must stay untouched.
		#
		mkdir -p "$ALT_ROOT"/stubboot/boot/grub
		cp "$ALT_ROOT"/boot/grub/menu.lst "$ALT_ROOT"/stubboot/boot/grub
		bootdev=`grep -v "^#" "$ALT_ROOT"/etc/vfstab | grep pcfs | \
			grep "[	 ]/stubboot[ 	]" | nawk '{print $1}'`
		rpcfsdev=`echo "$bootdev" | sed -e "s/dev\/dsk/dev\/rdsk/"`
		if [ X"$rpcfsdev" != X ]; then
			print "Installing grub on $rpcfsdev"
			"$ALT_ROOT"/sbin/installgrub $STAGE1 $STAGE2 $rpcfsdev
		fi
	fi

	get_rootdev_list | while read rootdev
	do
		if [ X"$rpcfsdev" != X ]; then
			echo "create GRUB menu in "$ALT_ROOT"/stubboot"
			"$ALT_ROOT"/sbin/bootadm update-menu \
			    -R "$ALT_ROOT"/stubboot -o $rootdev,"$ALT_ROOT"
		else
			echo "Creating GRUB menu in ${ALT_ROOT:-/}"
			$ALT_ROOT/sbin/bootadm update-menu -R ${ALT_ROOT:-/} \
			    -o $rootdev
		fi
		print "Installing grub on $rootdev"
		"$ALT_ROOT"/sbin/installgrub $STAGE1 $STAGE2 $rootdev
	done
}

if [ -f "$ALT_ROOT"/platform/i86pc/multiboot -a "$ARCH" = i386 ] ; then
	check_pcfs_boot
	install_grub
fi

exit 0
