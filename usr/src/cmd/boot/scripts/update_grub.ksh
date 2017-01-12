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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2016 Nexenta Systems, Inc.
#

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
is_zfs_boot=no

check_pcfs_boot()
{
	bootdev=`grep -v "^#" "$ALT_ROOT"/etc/vfstab | grep pcfs \
	    | grep "[       ]/stubboot[      ]" | nawk '{print $1}'`
	if [ X"$bootdev" = "X" ]; then
		is_pcfs_boot=no
	fi
}

check_zfs_boot()
{
	if [ -f "$ALT_ROOT"/etc/lu/GRUB_slice ]; then
		dev=`grep '^PHYS_SLICE=' "$ALT_ROOT"/etc/lu/GRUB_slice |
		    cut -d= -f2`
		if [ "`fstyp $dev`" = "zfs" ]; then
			is_zfs_boot=yes
		fi
	else
		rootfstype=`df -n ${ALT_ROOT:-/} | awk '{print $3}'`
		if [ "$rootfstype" = "zfs" ]; then
			is_zfs_boot=yes
		fi
			
	fi
}

#
# Return the list of raw devices
#
get_rootdev_list()
{
	if [ -f "$ALT_ROOT"/etc/lu/GRUB_slice ]; then
		dev=`grep '^PHYS_SLICE' "$ALT_ROOT"/etc/lu/GRUB_slice |
		    cut -d= -f2`
		if [ "$is_zfs_boot" = "yes" ]; then
			fstyp -a "$dev" | grep 'path: ' | grep -v phys_path: | 
			    cut -d"'" -f2 | sed 's+/dsk/+/rdsk/+'
		else
			echo "$dev"
		fi
		return
	elif [ "$is_zfs_boot" = "yes" ]; then
		rootpool=`df -k ${ALT_ROOT:-/} | tail +2 | cut -d/ -f1`
		rootdevlist=`LC_ALL=C zpool iostat -v "$rootpool" | tail +5 |
		    egrep -v "mirror|spare|replacing" |
		    sed -n -e '/--/q' -e p | awk '{print $1}'`
	else
		dev=`grep -v "^#" "$ALT_ROOT"/etc/vfstab | \
		    grep "[      ]/[    ]" | nawk '{print $2}'`
		if [[ $dev = /dev/rdsk/* ]]; then
			rootdevlist=`basename "$dev"`
		fi
	fi
	for rootdev in $rootdevlist
	do
		echo /dev/rdsk/`basename $rootdev`
	done
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

	grubdevlist=`get_rootdev_list`
	zfsarg=""
	if [ "$is_zfs_boot" = "yes" ]; then
		zfsarg="-Z"
	fi

	for rootdev in $grubdevlist
	do
		if [ X"$rpcfsdev" != X ]; then
			echo "create GRUB menu in "$ALT_ROOT"/stubboot"
			"$ALT_ROOT"/sbin/bootadm update-menu $zfsarg\
			    -R "$ALT_ROOT"/stubboot -o $rootdev,"$ALT_ROOT"
		else
			echo "Creating GRUB menu in ${ALT_ROOT:-/}"
			$ALT_ROOT/sbin/bootadm update-menu -R ${ALT_ROOT:-/} \
			    $zfsarg -o $rootdev
		fi
		print "Installing grub on $rootdev"
		"$ALT_ROOT"/sbin/installgrub $STAGE1 $STAGE2 $rootdev
	done
}

if [ -f "$ALT_ROOT"/platform/i86pc/multiboot -a "$ARCH" = i386 ] ; then
	check_pcfs_boot
	check_zfs_boot
	install_grub
fi

exit 0
