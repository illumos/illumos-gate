#!/bin/ksh
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
	cd "$MINIROOT/usr"
	find openwin dt -print | cpio -ocmPuB 2> /dev/null | bzip2 > \
	    "$CPIO_DIR/X.cpio.bz2"

	find openwin/bin/mkfontdir \
	     openwin/lib/installalias \
	     openwin/server/lib/libfont.so.1 \
	     openwin/server/lib/libtypesclr.so.0 \
	         -print | cpio -ocmPuB 2> /dev/null | bzip2 > \
	         "$CPIO_DIR/X_small.cpio.bz2"

	rm -rf dt openwin
	ln -s ../tmp/root/usr/dt
	ln -s ../tmp/root/usr/openwin
	cd ../..
}

packmedia()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	mkdir -p "$MEDIA/$RELEASE/Tools/Boot"
	mkdir -p "$MEDIA/boot"

	cd "$MINIROOT"

	# archive package databases to conserve memory
	#
	find tmp/root/var/sadm/install tmp/root/var/sadm/pkg -print | \
	    cpio -ocmPuB 2> /dev/null | bzip2 > \
	    "$MEDIA/$RELEASE/Tools/Boot/pkg_db.cpio.bz2"

	rm -rf "$MINIROOT/tmp/root/var/sadm/install"
	rm -rf "$MINIROOT/tmp/root/var/sadm/pkg"

	archive_X "$MEDIA" "$MINIROOT"

	# clear out 64 bit support to conserve memory
	#
	find "$MINIROOT" -name amd64 -type directory | xargs rm -rf

	cp "$MINIROOT/platform/i86pc/multiboot" "$MEDIA/boot"

	# copy the install menu to menu.lst so we have a menu
	# on the install media
	#
	if [ -f "${MINIROOT}/boot/grub/install_menu" ] ; then
		cp ${MINIROOT}/boot/grub/install_menu \
		    ${MEDIA}/boot/grub/menu.lst
	fi

	cd "$MEDIA/$RELEASE/Tools/Boot"
	ln -sf ../../../boot/x86.miniroot
	ln -sf ../../../boot/multiboot
	ln -sf ../../../boot/grub/pxegrub
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
	cd "$UNPACKED_ROOT/usr"
	rm -rf dt openwin
	bzcat "$CPIO_DIR/X.cpio.bz2" | cpio -icdmu 2> /dev/null
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
	cd "$UNPACKED_ROOT"
	bzcat "$MEDIA/$RELEASE/Tools/Boot/pkg_db.cpio.bz2" | cpio -icdmu \
	    2> /dev/null
}

do_unpack()
{
	rm -rf "$UNPACKED_ROOT"
	mkdir -p "$UNPACKED_ROOT"
	cd $MNT
	find . -print | cpio -pdum "$UNPACKED_ROOT" 2> /dev/null
	cd "$BASE"
	umount $MNT
}

unpack()
{

	if [ ! -f "$MR" ] ; then
		usage
		exit 1
	fi

	TMR=/tmp/mr$$
	gzcat "$MR" > $TMR

	lofidev=`/usr/sbin/lofiadm -a $TMR`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	mkdir -p $MNT

	FSTYP=`fstyp $lofidev`

	if [ "$FSTYP" = ufs ] ; then
		/usr/sbin/mount -o ro,nologging $lofidev $MNT
		do_unpack
	elif [ "$FSTYP" = hsfs ] ; then
		/usr/sbin/mount -F hsfs -o ro $lofidev $MNT
		do_unpack
	else
		printf "invalid root archive\n"
	fi

	rmdir $MNT
	lofiadm -d $TMR
	rm $TMR
}

pack()
{
	if [ ! -d "$UNPACKED_ROOT" -o -z "$MR" ] ; then
		usage
		exit 1
	fi

	size=`du -sk "$UNPACKED_ROOT" | ( read size name; echo $size )`
	size=`expr $size + \( $size \* 10 \) / 100`
	rm -f "$MR"
	/usr/sbin/mkfile ${size}k "$MR"

	lofidev=`/usr/sbin/lofiadm -a "$MR"`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	rlofidev=`echo $lofidev | sed s/lofi/rlofi/`
	newfs $rlofidev < /dev/null 2> /dev/null 
	mkdir -p $MNT
	mount -o nologging $lofidev $MNT 
	rmdir $MNT/lost+found
	cd "$UNPACKED_ROOT"
	find . -print | cpio -pdum $MNT 2> /dev/null
	lockfs -f $MNT
	umount $MNT
	rmdir $MNT
	lofiadm -d "$MR"

	cd "$BASE"

	rm -f "$MR.gz"
	gzip -f "$MR"
	mv "$MR.gz" "$MR"
	chmod a+r "$MR"
}

# main
#

if [ $# != 3 ] ; then
	usage
	exit 1
fi

UNPACKED_ROOT="$3"
BASE="`pwd`"
MNT=/tmp/mnt$$
MR="$2"

if [ "`dirname $MR`" = . ] ; then
	MR="$BASE/$MR"
fi
if [ "`dirname $UNPACKED_ROOT`" = . ] ; then
	UNPACKED_ROOT="$BASE/$UNPACKED_ROOT"
fi

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
