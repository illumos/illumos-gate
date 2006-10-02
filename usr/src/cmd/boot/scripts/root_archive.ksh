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

# Copyright 2006 Sun Microsystems, Inc.  All rights reserved. 
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

# utility to pack and unpack a boot/root archive
# both ufs and hsfs (iso9660) format archives are unpacked
# only ufs archives are generated
#
# usage: pack   <archive> <root>
#        unpack <archive> <root>
#        packmedia   <solaris_image> <root>
#        unpackmedia <solaris_image> <root>
#
#   Where <root> is the directory to unpack to and will be cleaned out
#   if it exists.
#
#   In the case of (un)packmedia, the image is packed or unpacked to/from
#   Solaris media and all the things that don't go into the ramdisk image
#   are (un)cpio'd as well
#
# This utility is also used to pack parts (in essence the window system, 
# usr/dt and usr/openwin) of the non ramdisk SPARC 
# miniroot. (un)packmedia will recognize that they are being run a SPARC 
# miniroot and do the appropriate work. 
#

usage()
{
	printf "usage: root_archive pack <archive> <root>\n"
	printf "       root_archive unpack <archive> <root>\n"
	printf "       root_archive packmedia   <solaris_image> <root>\n"
	printf "       root_archive unpackmedia <solaris_image> <root>\n"
}

cleanup()
{
	if [ -d $MNT ] ; then
		umount $MNT 2> /dev/null
		rmdir $MNT
	fi

	lofiadm -d "$TMR" 2>/dev/null
	rm -f "$TMR" "$TMR.gz"
}

archive_X()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		CPIO_DIR="$MEDIA/$RELEASE/Tools/miniroot_extra"
		mkdir -p "$CPIO_DIR"
	else
		CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"
	fi

	# create the graphics and non-graphics X archive
	#
	(
		cd "$MINIROOT/usr"
		find openwin dt X11 -print 2> /dev/null |\
		    cpio -ocmPuB 2> /dev/null | bzip2 > "$CPIO_DIR/X.cpio.bz2"

		find openwin/bin/mkfontdir \
		     openwin/lib/installalias \
		     openwin/server/lib/libfont.so.1 \
		     openwin/server/lib/libtypesclr.so.0 \
			 -print | cpio -ocmPuB 2> /dev/null | bzip2 > \
			 "$CPIO_DIR/X_small.cpio.bz2"

		rm -rf dt openwin X11
		ln -s ../tmp/root/usr/dt
		ln -s ../tmp/root/usr/openwin
		ln -s ../tmp/root/usr/X11
	)
}

packmedia()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	mkdir -p "$MEDIA/$RELEASE/Tools/Boot"
	mkdir -p "$MEDIA/boot"

	# archive package databases to conserve memory
	#
	(
		cd "$MINIROOT"
		find tmp/root/var/sadm/install tmp/root/var/sadm/pkg -print | \
		    cpio -ocmPuB 2> /dev/null | bzip2 > \
		    "$MEDIA/$RELEASE/Tools/Boot/pkg_db.cpio.bz2"
	)

	rm -rf "$MINIROOT/tmp/root/var/sadm/install"
	rm -rf "$MINIROOT/tmp/root/var/sadm/pkg"

	# clear out 64 bit support to conserve memory
	#
	if [ "$STRIP_AMD64" != false ] ; then
		find "$MINIROOT" -name amd64 -type directory | xargs rm -rf
	fi

	archive_X "$MEDIA" "$MINIROOT"

	cp "$MINIROOT/platform/i86pc/multiboot" "$MEDIA/boot"

	# copy the install menu to menu.lst so we have a menu
	# on the install media
	#
	if [ -f "${MINIROOT}/boot/grub/install_menu" ] ; then
		cp ${MINIROOT}/boot/grub/install_menu \
		    ${MEDIA}/boot/grub/menu.lst
	fi

	(
		cd "$MEDIA/$RELEASE/Tools/Boot"
		ln -sf ../../../boot/x86.miniroot
		ln -sf ../../../boot/multiboot
		ln -sf ../../../boot/grub/pxegrub
	)
}

unarchive_X()
{
	MEDIA="$1"
	UNPACKED_ROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		CPIO_DIR="$MEDIA/$RELEASE/Tools/miniroot_extra"
	else
		CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"
	fi

	# unpack X
	#
	(
		cd "$UNPACKED_ROOT/usr"
		rm -rf dt openwin X11
		bzcat "$CPIO_DIR/X.cpio.bz2" | cpio -icdmu 2> /dev/null
	)
}

unpackmedia()
{
	MEDIA="$1"
	UNPACKED_ROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	unarchive_X "$MEDIA" "$UNPACKED_ROOT"

	# unpack package databases
	#
	(
		cd "$UNPACKED_ROOT"
		bzcat "$MEDIA/$RELEASE/Tools/Boot/pkg_db.cpio.bz2" |
		    cpio -icdmu 2> /dev/null
	)
}

do_unpack()
{
	rm -rf "$UNPACKED_ROOT"
	mkdir -p "$UNPACKED_ROOT"
	(
		cd $MNT
		find . -print | cpio -pdum "$UNPACKED_ROOT" 2> /dev/null
	)
	umount $MNT
}

unpack()
{

	if [ ! -f "$MR" ] ; then
		usage
		exit 1
	fi

	gzcat "$MR" > $TMR

	LOFIDEV=`/usr/sbin/lofiadm -a $TMR`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	mkdir -p $MNT

	FSTYP=`fstyp $LOFIDEV`

	if [ "$FSTYP" = ufs ] ; then
		/usr/sbin/mount -o ro,nologging $LOFIDEV $MNT
		do_unpack
	elif [ "$FSTYP" = hsfs ] ; then
		/usr/sbin/mount -F hsfs -o ro $LOFIDEV $MNT
		do_unpack
	else
		printf "invalid root archive\n"
	fi

	rmdir $MNT
	lofiadm -d $TMR ; LOFIDEV=
	rm $TMR
}

pack()
{
	if [ ! -d "$UNPACKED_ROOT" -o -z "$MR" ] ; then
		usage
		exit 1
	fi

	# Estimate image size and add %10 overhead for ufs stuff.
	# Note, we can't use du here in case $UNPACKED_ROOT is on a filesystem,
	# e.g. zfs, in which the disk usage is less than the sum of the file
	# sizes.  The nawk code 
	#
	#	{t += ($7 % 1024) ? (int($7 / 1024) + 1) * 1024 : $7}
	#
	# below rounds up the size of a file/directory, in bytes, to the
	# next multiple of 1024.  This mimics the behavior of ufs especially
	# with directories.  This results in a total size that's slightly
	# bigger than if du was called on a ufs directory.
	size=$(find "$UNPACKED_ROOT" -ls | nawk '
	    {t += ($7 % 1024) ? (int($7 / 1024) + 1) * 1024 : $7}
	    END {print int(t * 1.10 / 1024)}')

	/usr/sbin/mkfile ${size}k "$TMR"

	LOFIDEV=`/usr/sbin/lofiadm -a "$TMR"`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	RLOFIDEV=`echo $LOFIDEV | sed s/lofi/rlofi/`
	newfs $RLOFIDEV < /dev/null 2> /dev/null 
	mkdir -p $MNT
	mount -o nologging $LOFIDEV $MNT 
	rmdir $MNT/lost+found
	(
		cd "$UNPACKED_ROOT"
		find . -print | cpio -pdum $MNT 2> /dev/null
	)
	lockfs -f $MNT
	umount $MNT
	rmdir $MNT
	lofiadm -d $LOFIDEV
	LOFIDEV=

	rm -f "$TMR.gz"
	gzip -f "$TMR"
	mv "$TMR.gz" "$MR"
	chmod a+r "$MR"
}

# main
#

EXTRA_SPACE=0
STRIP_AMD64=

while getopts s:6 opt ; do
	case $opt in
	s)	EXTRA_SPACE="$OPTARG"
		;;
	6)	STRIP_AMD64=false
		;;
	*)	usage
		exit 1
		;;
	esac
done
shift `expr $OPTIND - 1`

if [ $# != 3 ] ; then
	usage
	exit 1
fi

UNPACKED_ROOT="$3"
BASE="`pwd`"
MNT=/tmp/mnt$$
TMR=/tmp/mr$$
LOFIDEV=
MR="$2"

if [ "`dirname $MR`" = . ] ; then
	MR="$BASE/$MR"
fi
if [ "`dirname $UNPACKED_ROOT`" = . ] ; then
	UNPACKED_ROOT="$BASE/$UNPACKED_ROOT"
fi

trap cleanup EXIT

case $1 in
	packmedia)
		MEDIA="$MR"
		MR="$MR/boot/x86.miniroot"

		if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
			archive_X "$MEDIA" "$UNPACKED_ROOT"
		else
			packmedia "$MEDIA" "$UNPACKED_ROOT"
			pack
		fi ;;
	unpackmedia)
		MEDIA="$MR"
		MR="$MR/boot/x86.miniroot"

		if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
			unarchive_X "$MEDIA" "$UNPACKED_ROOT"
		else
			unpack
			unpackmedia "$MEDIA" "$UNPACKED_ROOT"
		fi ;;
	pack)	pack ;;
	unpack)	unpack ;;
	*)	usage ;;
esac
