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

# ident	"%Z%%M%	%I%	%E% SMI"

format=ufs
ALT_ROOT=
NO_AMD64=

BOOT_ARCHIVE=platform/i86pc/boot_archive

export PATH=$PATH:/usr/sbin:/usr/bin:/sbin

#
# Parse options
#
while getopts R: OPT 2> /dev/null
do
        case $OPT in
        R)      ALT_ROOT="$OPTARG"
		if [ "$ALT_ROOT" != "/" ]; then
			echo "Creating ram disk for $ALT_ROOT"
		fi
		;;
        ?)      echo Usage: ${0##*/}: [-R \<root\>]
		exit ;;
        esac
done

if [ -x /usr/bin/mkisofs -o -x /tmp/bfubin/mkisofs ] ; then
	format=isofs
fi

#
# mkisofs on s8 doesn't support functionality used by GRUB boot.
# Use ufs format for boot archive instead.
#
release=`uname -r`
if [ "$release" = "5.8" ]; then
   format=ufs
fi

shift `expr $OPTIND - 1`

if [ $# -eq 1 ]; then
	ALT_ROOT="$1"
	echo "Creating ram disk for $ALT_ROOT"
fi

function cleanup
{
	umount -f "$rdmnt" 2>/dev/null
	lofiadm -d "$rdfile" 2>/dev/null
	rm -fr "$rddir" 2> /dev/null
}

function getsize
{
	# Estimate image size, add %10 overhead for ufs stuff
	total_size=0
	for file in $filelist
	do
		if [ -e "$ALT_ROOT/$file" ] ; then
			du -sk "$ALT_ROOT/$file" | read size name
			(( total_size += size ))
		fi
	done
	(( total_size += total_size * 10 / 100 ))
}

function create_ufs
{
	# should we exclude amd64 binaries?
	[ $is_amd64 -eq 0 ] && NO_AMD64="-name amd64 -prune"


	mkfile ${total_size}k "$rdfile"
	lofidev=`lofiadm -a "$rdfile"`
	newfs $lofidev < /dev/null 2> /dev/null
	mkdir "$rdmnt"
	mount -F mntfs mnttab /etc/mnttab > /dev/null 2>&1
	mount -o nologging $lofidev "$rdmnt"

	# do the actual copy
	cd "/$ALT_ROOT"

	find $filelist -print $NO_AMD64 2> /dev/null | \
	     cpio -pdum "$rdmnt" 2> /dev/null
	umount "$rdmnt"
	lofiadm -d "$rdfile"
	rmdir "$rdmnt"

	# Check if gzip exists in /usr/bin, so we only try to run gzip
	# on systems that have gzip. Then run gzip out of the patch to
	# pick it up from bfubin or something like that if needed.
	#
	if [ -x /usr/bin/gzip ] ; then
		gzip -c "$rdfile" > "$ALT_ROOT/$BOOT_ARCHIVE-new"
	else
		cat "$rdfile" > "$ALT_ROOT/$BOOT_ARCHIVE-new"
	fi
}

function create_isofs
{
	# should we exclude amd64 binaries?
	[ $is_amd64 = 0 ] && NO_AMD64="-m amd64"

	# create image directory seed with graft points
	mkdir "$rdmnt"
	files=
	isocmd="mkisofs -quiet -graft-points -dlrDJN -relaxed-filenames $NO_AMD64"
	for path in $filelist
	do
		if [ -d "$ALT_ROOT/$path" ]; then
			isocmd="$isocmd $path/=\"$ALT_ROOT/$path\""
			mkdir -p "$rdmnt/$path"
		elif [ -f "$ALT_ROOT/$path" ]; then
			files="$files $path"
		fi
	done
	cd "/$ALT_ROOT"
	find $files 2> /dev/null | cpio -pdum "$rdmnt" 2> /dev/null
	isocmd="$isocmd \"$rdmnt\""
	rm -f "$errlog"

	# Check if gzip exists in /usr/bin, so we only try to run gzip
	# on systems that have gzip. Then run gzip out of the patch to
	# pick it up from bfubin or something like that if needed.
	#
	if [ -x /usr/bin/gzip ] ; then
		ksh -c "$isocmd" 2> "$errlog" | \
		    gzip > "$ALT_ROOT/$BOOT_ARCHIVE-new"
	else
		ksh -c "$isocmd" 2> "$errlog" > "$ALT_ROOT/$BOOT_ARCHIVE-new"
	fi

	if [ -s "$errlog" ]; then
		grep Error: "$errlog" >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			grep Error: "$errlog"
			rm -f "$ALT_ROOT/$BOOT_ARCHIVE-new"
		fi
	fi
	rm -f "$errlog"
}

#
# get filelist
#
files="$ALT_ROOT/boot/solaris/filelist.ramdisk"
if [ -f "$ALT_ROOT/etc/boot/solaris/filelist.ramdisk" ]; then
	files="$files \"$ALT_ROOT/etc/boot/solaris/filelist.ramdisk\""
fi
filelist=`cat "$files" | sort -u`

#
# decide if cpu is amd64 capable
#
prtconf -v /devices | grep CPU_not_amd64 > /dev/null 2>&1
is_amd64=$?

scratch=tmp

if [ $format = ufs ] ; then
	# calculate image size
	getsize

	# check to see if there is sufficient space in tmpfs 
	#
	tmp_free=`df -b /tmp | tail -1 | awk '{ printf ($2) }'`
	(( tmp_free = tmp_free / 2 ))

	if [ $total_size -gt $tmp_free  ] ; then
		# assumes we have enough scratch space on $ALT_ROOT
        	scratch="$ALT_ROOT"
	fi
fi

rddir="/$scratch/create_ramdisk.$$.tmp"
rdfile="$rddir/rd.file"
rdmnt="$rddir/rd.mount"
errlog="$rddir/rd.errlog"

# make directory for temp files safely
rm -rf "$rddir"
mkdir "$rddir"

# Clean up upon exit.
trap 'cleanup' EXIT

echo "updating $ALT_ROOT/$BOOT_ARCHIVE...this may take a minute"

if [ $format = "ufs" ]; then
	create_ufs
else
	create_isofs
fi

# sanity check the archive before moving it into place
# the file type check also establishes that the file exists at all
#
ARCHIVE_SIZE=`du -k "$ALT_ROOT/$BOOT_ARCHIVE-new" | cut -f 1`
file "$ALT_ROOT/$BOOT_ARCHIVE-new" | grep gzip > /dev/null

if [ $? = 1 ] && [ -x /usr/bin/gzip ] || [ $ARCHIVE_SIZE -lt 5000 ]; then
	echo "update of $ALT_ROOT/$BOOT_ARCHIVE failed"
	rm -rf "$rddir"
	exit 1
fi

#
# For the diskless case, hardlink archive to /boot to make it
# visible via tftp. /boot is lofs mounted under /tftpboot/<hostname>.
# NOTE: this script must work on both client and server
#
grep "[	 ]/[	 ]*nfs[	 ]" "$ALT_ROOT/etc/vfstab" > /dev/null
if [ $? = 0 ]; then
	mv "$ALT_ROOT/$BOOT_ARCHIVE-new" "$ALT_ROOT/$BOOT_ARCHIVE"
	rm -f "$ALT_ROOT/boot/boot_archive"
	ln "$ALT_ROOT/$BOOT_ARCHIVE" "$ALT_ROOT/boot/boot_archive"
	rm -rf "$rddir"
	exit
fi

lockfs -f "/$ALT_ROOT"
mv "$ALT_ROOT/$BOOT_ARCHIVE-new" "$ALT_ROOT/$BOOT_ARCHIVE"
lockfs -f "/$ALT_ROOT"

rm -rf "$rddir"
