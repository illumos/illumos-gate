#!/bin/ksh -p
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#
# basic setup
#
rddir=/tmp/create_ramdisk.$$.tmp
rdfile=${rddir}/rd.file
rdmnt=${rddir}/rd.mount
errlog=${rddir}/rd.errlog

format=ufs
ALT_ROOT=
NO_AMD64=

BOOT_ARCHIVE=platform/i86pc/boot_archive

export PATH=${PATH}:/usr/sbin:/usr/bin:/sbin

#
# Parse options
#
while getopts R: OPT 2> /dev/null
do
        case $OPT in
        R)      ALT_ROOT="$OPTARG"
		if [ "$ALT_ROOT" != "/" ]; then
			echo "Creating ram disk on ${ALT_ROOT}"
		fi
		;;
        ?)      echo Usage: ${0##*/}: [-R \<root\>]
		exit ;;
        esac
done

if [ -x /usr/bin/mkisofs -o -x /tmp/bfubin/mkisofs ] ; then
	format=isofs
fi

shift `expr $OPTIND - 1`

if [ $# -eq 1 ]; then
	ALT_ROOT=$1
	echo "Creating ram disk on ${ALT_ROOT}"
fi

# make directory for temp files safely
rm -rf ${rddir}
mkdir ${rddir}

# Clean up upon exit.
trap 'cleanup' EXIT

function cleanup {
	umount -f ${rdmnt} 2>/dev/null
	lofiadm -d ${rdfile} 2>/dev/null
	rm -fr ${rddir} 2> /dev/null
}

function getsize {
	# Estimate image size, add %10 overhead for ufs stuff
	total_size=0
	for file in $filelist
	do
		du -sk ${ALT_ROOT}/${file} | read size name
		(( total_size += size ))
	done
	(( total_size += total_size * 10 / 100 ))
}

function create_ufs
{
	# should we exclude amd64 binaries?
	[ $is_amd64 -eq 0 ] && NO_AMD64="-name amd64 -prune"

	# calculate image size
	getsize

	mkfile ${total_size}k ${rdfile}
	lofidev=`lofiadm -a ${rdfile}`
	newfs ${lofidev} < /dev/null 2> /dev/null
	mkdir ${rdmnt}
	mount -F mntfs mnttab /etc/mnttab > /dev/null 2>&1
	mount -o nologging ${lofidev} ${rdmnt}


	# do the actual copy
	cd /${ALT_ROOT}
	find $filelist -print ${NO_AMD64}| cpio -pdum ${rdmnt} 2> /dev/null
	umount ${rdmnt}
	lofiadm -d ${rdfile}
	rmdir ${rdmnt}
	gzip -c ${rdfile} > ${ALT_ROOT}/${BOOT_ARCHIVE}-new
}

function create_isofs
{
	# should we exclude amd64 binaries?
	[ $is_amd64 = 0 ] && NO_AMD64="-m amd64"

	# create image directory seed with graft points
	mkdir ${rdmnt}
	files=
	isocmd="mkisofs -quiet -graft-points -dlrDJN -relaxed-filenames ${NO_AMD64}"
	for path in $filelist
	do
		if [ -d ${ALT_ROOT}/$path ]; then
			isocmd="$isocmd $path/=${ALT_ROOT}/$path"
			mkdir -p ${rdmnt}/$path
		elif [ -f ${ALT_ROOT}/$path ]; then
			files="$files $path"
		else
			echo "/${ALT_ROOT}/$path not present"
		fi
	done
	cd /${ALT_ROOT}
	find $files 2> /dev/null | cpio -pdum ${rdmnt} 2> /dev/null
	isocmd="$isocmd ${rdmnt}"
	rm -f ${errlog}
	${isocmd} 2> ${errlog} | gzip > ${ALT_ROOT}/${BOOT_ARCHIVE}-new
	if [ -s ${errlog} ]; then
		grep Error: ${errlog} >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			grep Error: ${errlog}
			rm -f ${ALT_ROOT}/${BOOT_ARCHIVE}-new
		fi
	fi
	rm -f ${errlog}
}

#
# get filelist
#
files=${ALT_ROOT}/boot/solaris/filelist.ramdisk
if [ -f ${ALT_ROOT}/etc/boot/solaris/filelist.ramdisk ]; then
	files="$files ${ALT_ROOT}/etc/boot/solaris/filelist.ramdisk"
fi
filelist=`cat $files | sort | uniq`

#
# decide if cpu is amd64 capable
#
prtconf -v /devices | grep CPU_not_amd64 > /dev/null 2>&1
is_amd64=$?

echo "updating ${ALT_ROOT}/${BOOT_ARCHIVE}...this may take a minute"

if [ $format = "ufs" ]; then
	create_ufs
else
	create_isofs
fi

if [ ! -f ${ALT_ROOT}/${BOOT_ARCHIVE}-new ]; then
	echo "update of ${ALT_ROOT}/${BOOT_ARCHIVE} failed"
	rm -rf ${rddir}
	exit 1
fi

#
# For the diskless case, hardlink archive to /boot to make it
# visible via tftp. /boot is lofs mounted under /tftpboot/<hostname>.
# NOTE: this script must work on both client and server
#
grep "[	 ]/[	 ]*nfs[	 ]" $ALT_ROOT/etc/vfstab > /dev/null
if [ $? = 0 ]; then
	mv ${ALT_ROOT}/${BOOT_ARCHIVE}-new ${ALT_ROOT}/${BOOT_ARCHIVE}
	rm -f ${ALT_ROOT}/boot/boot_archive
	ln ${ALT_ROOT}/${BOOT_ARCHIVE} ${ALT_ROOT}/boot/boot_archive
	rm -rf ${rddir}
	exit
fi

lockfs -f /$ALT_ROOT
mv ${ALT_ROOT}/${BOOT_ARCHIVE}-new ${ALT_ROOT}/${BOOT_ARCHIVE}
lockfs -f /$ALT_ROOT

rm -rf ${rddir}
