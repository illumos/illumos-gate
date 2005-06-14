#!/bin/ksh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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

# Copyright 2005 Sun Microsystems, Inc.  All rights reserved. 
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

usage()
{
	printf "usage: root_archive pack <archive> <root>\n"
	printf "       root_archive unpack <archive> <root>\n"
	printf "       root_archive packmedia   <solaris_image> <root>\n"
	printf "       root_archive unpackmedia <solaris_image> <root>\n"
}

packmedia()
{
	MEDIA=$1
	MINIROOT=$2

	RELEASE=`ls -d ${MEDIA}/Solaris_*`
	RELEASE=`basename ${RELEASE}`

	mkdir -p ${MEDIA}/${RELEASE}/Tools/Boot
	mkdir -p ${MEDIA}/boot

	cd ${MINIROOT}

	# archive package databases to conserve memory
	#
	find tmp/root/var/sadm/install tmp/root/var/sadm/pkg -print | \
	    cpio -ocmPuB 2> /dev/null | bzip2 > \
	    ${MEDIA}/${RELEASE}/Tools/Boot/pkg_db.cpio.bz2

	rm -rf ${MINIROOT}/tmp/root/var/sadm/install
	rm -rf ${MINIROOT}/tmp/root/var/sadm/pkg

	# create the graphics and non-graphics X archive
	#
	cd ${MINIROOT}/usr
	find openwin dt -print | cpio -ocmPuB 2> /dev/null | bzip2 > \
	    ${MEDIA}/${RELEASE}/Tools/Boot/X.cpio.bz2

	find openwin/bin/mkfontdir \
	     openwin/lib/installalias \
	     openwin/server/lib/libfont.so.1 \
	     openwin/server/lib/libtypesclr.so.0 \
	         -print | cpio -ocmPuB 2> /dev/null | bzip2 > \
	         ${MEDIA}/${RELEASE}/Tools/Boot/X_small.cpio.bz2

	rm -rf dt openwin
	ln -s ../tmp/root/usr/dt
	ln -s ../tmp/root/usr/openwin
	cd ../..

	# clear out 64 bit support to conserve memory
	#
	find ${MINIROOT} -name amd64 -type directory | xargs rm -rf

	cp ${MINIROOT}/platform/i86pc/multiboot ${MEDIA}/boot

	# XXX fix as soon as we deliver boot/grub/install_menu
	#
	if [ -f "${MINIROOT}/boot/grub/install_menu" ] ; then
		cp ${MINIROOT}/boot/grub/install_menu \
		    ${MEDIA}/boot/grub/menu.lst
	elif [ -f "/ws/boot-gate/usr/src/grub/menu.lst.cd_dvd" ] ; then
		cp /ws/boot-gate/usr/src/grub/menu.lst.cd_dvd \
		    ${MEDIA}/boot/grub/menu.lst
	elif [ -f "/ws/boot-gate/usr/src/grub/install_menu" ] ; then
		cp /ws/boot-gate/usr/src/grub/install_menu \
		    ${MEDIA}/boot/grub/menu.lst
	fi

	cd ${MEDIA}/${RELEASE}/Tools/Boot
	ln -sf ../../../boot/x86.miniroot
	ln -sf ../../../boot/multiboot
	ln -sf ../../../boot/grub/pxegrub

	# XXX fix once SUNWgzip is included in the miniroot
	if [ ! -f "${MINIROOT}/usr/bin/gzip" ] ; then
		cp /usr/bin/gzip ${MINIROOT}/usr/bin
	fi
}

unpackmedia()
 {
	MEDIA=$1
	UNPACKED_ROOT=$2

	RELEASE=`ls -d ${MEDIA}/Solaris_*`
	RELEASE=`basename ${RELEASE}`

	# unpack X
	#
	cd ${UNPACKED_ROOT}/usr
	rm -rf dt openwin
	bzcat ${MEDIA}/${RELEASE}/Tools/Boot/X.cpio.bz2 | cpio -icdmu \
	    2> /dev/null

	# unpack package databases
	#
	cd $UNPACKED_ROOT
	bzcat ${MEDIA}/${RELEASE}/Tools/Boot/pkg_db.cpio.bz2 | cpio -icdmu \
	    2> /dev/null
}

do_unpack()
{
	rm -rf $UNPACKED_ROOT
	mkdir $UNPACKED_ROOT
	cd $MNT
	find . -print | cpio -pdum $UNPACKED_ROOT 2> /dev/null
	cd $BASE
	umount $MNT
}

unpack()
{

	if [ ! -f "${MR}" ] ; then
		usage
		exit 1
	fi

	TMR=/tmp/mr$$
	gzcat $MR > $TMR

	lofidev=`/usr/sbin/lofiadm -a $TMR`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	mkdir $MNT

	FSTYP=`fstyp ${lofidev}`

	if [ "${FSTYP}" = ufs ] ; then
		/usr/sbin/mount -o ro,nologging $lofidev $MNT
		do_unpack
	elif [ "${FSTYP}" = hsfs ] ; then
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
	if [ ! -d "${UNPACKED_ROOT}" -o "X${MR}" = "X" ] ; then
		usage
		exit 1
	fi

	size=`du -sk ${UNPACKED_ROOT} | (read size name; echo ${size})`
	size=`expr $size + \( $size \* 10 \) / 100`
	rm -f ${MR}
	/usr/sbin/mkfile ${size}k $MR

	lofidev=`/usr/sbin/lofiadm -a $MR`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	rlofidev=`echo $lofidev | sed s/lofi/rlofi/`
	newfs $rlofidev < /dev/null 2> /dev/null 
	mkdir $MNT
	mount -o nologging $lofidev $MNT 
	rmdir ${MNT}/lost+found
	cd $UNPACKED_ROOT
	find . -print | cpio -pdum $MNT 2> /dev/null
	lockfs -f $MNT
	umount $MNT
	rmdir $MNT
	lofiadm -d $MR

	cd $BASE

	rm -f ${MR}.gz
	gzip -f $MR
	mv ${MR}.gz $MR
	chmod a+r $MR
}

# main
#

if [ $# != 3 ] ; then
	usage
	exit 1
fi

UNPACKED_ROOT=$3
BASE=`pwd`
MNT=/tmp/mnt$$
MR=$2

if [ "`dirname $MR`" = . ] ; then
	MR=${BASE}/${MR}
fi
if [ "`dirname $UNPACKED_ROOT`" = . ] ; then
	UNPACKED_ROOT=${BASE}/${UNPACKED_ROOT}
fi

case $1 in
	packmedia)
		MEDIA=$MR
		MR=${MR}/boot/x86.miniroot
		packmedia $MEDIA $UNPACKED_ROOT
		pack ;;
	unpackmedia)
		MEDIA=$MR
		MR=${MR}/boot/x86.miniroot
		unpack
		unpackmedia $MEDIA $UNPACKED_ROOT ;;
	pack)	pack ;;
	unpack)	unpack ;;
	*)	usage ;;
esac
