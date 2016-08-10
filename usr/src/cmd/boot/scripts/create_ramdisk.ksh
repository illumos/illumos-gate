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

# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2014 by Delphix. All rights reserved.
#

format=ufs
ALT_ROOT=
EXTRACT_ARGS=
compress=yes
SPLIT=unknown
ERROR=0
dirsize32=0
dirsize64=0

usage() {
	echo "This utility is a component of the bootadm(1M) implementation"
	echo "and it is not recommended for stand-alone use."
	echo "Please use bootadm(1M) instead."
	echo ""
	echo "Usage: ${0##*/}: [-R \<root\>] [-p \<platform\>] [--nocompress]"
	echo "where \<platform\> is one of i86pc, sun4u or sun4v"
	exit
}

# default platform is what we're running on
PLATFORM=`uname -m`

#
# set path, but inherit /tmp/bfubin if owned by
# same uid executing this process, which must be root.
#
if [ "`echo $PATH | cut -f 1 -d :`" = /tmp/bfubin ] && \
    [ -O /tmp/bfubin ] ; then
	export PATH=/tmp/bfubin
	export GZIP_CMD=/tmp/bfubin/gzip
else
	export PATH=/usr/sbin:/usr/bin:/sbin
	export GZIP_CMD=/usr/bin/gzip
fi

EXTRACT_FILELIST="/boot/solaris/bin/extract_boot_filelist"

#
# Parse options
#
while [ "$1" != "" ]
do
        case $1 in
        -R)	shift
		ALT_ROOT="$1"
		if [ "$ALT_ROOT" != "/" ]; then
			echo "Creating boot_archive for $ALT_ROOT"
			EXTRACT_ARGS="${EXTRACT_ARGS} -R ${ALT_ROOT}"
			EXTRACT_FILELIST="${ALT_ROOT}${EXTRACT_FILELIST}"
		fi
		;;
	-n|--nocompress) compress=no
		;;
	-p)	shift
		PLATFORM="$1"
		EXTRACT_ARGS="${EXTRACT_ARGS} -p ${PLATFORM}"
		;;
        *)      usage
		;;
        esac
	shift
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
	echo "Creating boot_archive for $ALT_ROOT"
fi

case $PLATFORM in
i386)	PLATFORM=i86pc
	ISA=i386
	ARCH64=amd64
	;;
i86pc)	ISA=i386
	ARCH64=amd64
	;;
sun4u)	ISA=sparc
	ARCH64=sparcv9
	;;
sun4v)	ISA=sparc
	ARCH64=sparcv9
	;;
*)	usage
	;;
esac

BOOT_ARCHIVE=platform/$PLATFORM/boot_archive
BOOT_ARCHIVE_64=platform/$PLATFORM/$ARCH64/boot_archive

if [ $PLATFORM = i86pc ] ; then
	if [ ! -x "$ALT_ROOT"/boot/solaris/bin/symdef ]; then
		# no dboot implies combined archives for example
		# live-upgrade from s9 to s10u6 is multiboot-only
		echo "Creating single archive at $ALT_ROOT/$BOOT_ARCHIVE"
		SPLIT=no
		compress=no
	else
		SPLIT=yes
	fi
else			# must be sparc
	SPLIT=no	# there's only 64-bit (sparcv9), so don't split
	compress=no	
fi

[ -x $GZIP_CMD ] || compress=no

function cleanup
{
	umount -f "$rdmnt32" 2>/dev/null
	umount -f "$rdmnt64" 2>/dev/null
	lofiadm -d "$rdfile32" 2>/dev/null
	lofiadm -d "$rdfile64" 2>/dev/null
	[ -n "$rddir" ] && rm -fr "$rddir" 2> /dev/null
	[ -n "$new_rddir" ] && rm -fr "$new_rddir" 2>/dev/null
}

function getsize
{
	# Estimate image size and add 10% overhead for ufs stuff.
	# Note, we can't use du here in case we're on a filesystem, e.g. zfs,
	# in which the disk usage is less than the sum of the file sizes.
	# The nawk code 
	#
	#	{t += ($5 % 1024) ? (int($5 / 1024) + 1) * 1024 : $5}
	#
	# below rounds up the size of a file/directory, in bytes, to the
	# next multiple of 1024.  This mimics the behavior of ufs especially
	# with directories.  This results in a total size that's slightly
	# bigger than if du was called on a ufs directory.
	size32=$(cat "$list32" | xargs -I {} ls -lLd "{}" 2> /dev/null |
		nawk '{t += ($5 % 1024) ? (int($5 / 1024) + 1) * 1024 : $5}
		END {print int(t * 1.10 / 1024)}')
	(( size32 += dirsize32 ))
	size64=$(cat "$list64" | xargs -I {} ls -lLd "{}" 2> /dev/null |
		nawk '{t += ($5 % 1024) ? (int($5 / 1024) + 1) * 1024 : $5}
		END {print int(t * 1.10 / 1024)}')
	(( size64 += dirsize64 ))
	(( total_size = size32 + size64 ))

	if [ $compress = yes ] ; then
		total_size=`echo $total_size | nawk '{print int($1 / 2)}'`
	fi
}

#
# Copies all desired files to a target directory.  One argument should be
# passed: the file containing the list of files to copy.  This function also
# depends on several variables that must be set before calling:
#
# $ALT_ROOT - the target directory
# $compress - whether or not the files in the archives should be compressed
# $rdmnt - the target directory
#
function copy_files
{
	list="$1"

	#
	# If compress is set, the files are gzip'd and put in the correct
	# location in the loop.  Nothing is printed, so the pipe and cpio
	# at the end is a nop.
	#
	# If compress is not set, the file names are printed, which causes
	# the cpio at the end to do the copy.
	#
	while read path
	do
		if [ $compress = yes ]; then
			dir="${path%/*}"
			[ -d "$rdmnt/$dir" ] || mkdir -p "$rdmnt/$dir"
			$GZIP_CMD -c "$path" > "$rdmnt/$path"
		else
			print "$path"
		fi
	done <"$list" | cpio -pdum "$rdmnt" 2>/dev/null

	if [ $ISA = sparc ] ; then
		# copy links
		find $filelist -type l -print 2>/dev/null |\
		    cpio -pdum "$rdmnt" 2>/dev/null
		if [ $compress = yes ] ; then
			# always copy unix uncompressed
			find $filelist -name unix -type f -print 2>/dev/null |\
			    cpio -pdum "$rdmnt" 2>/dev/null
		fi
	fi

}

#
# The first argument can be:
#
# "both" - create an archive with both 32-bit and 64-bit binaries
# "32-bit" - create an archive with only 32-bit binaries
# "64-bit" - create an archive with only 64-bit binaries
#
function create_ufs
{
	which=$1
	archive=$2
	lofidev=$3

	# should we exclude amd64 binaries?
	if [ "$which" = "32-bit" ]; then
		rdfile="$rdfile32"
		rdmnt="$rdmnt32"
		list="$list32"
	elif [ "$which" = "64-bit" ]; then
		rdfile="$rdfile64"
		rdmnt="$rdmnt64"
		list="$list64"
	else
		rdfile="$rdfile32"
		rdmnt="$rdmnt32"
		list="$list32"
	fi

	NOINUSE_CHECK=1 newfs $lofidev < /dev/null 2> /dev/null
	mkdir "$rdmnt"
	mount -F mntfs mnttab /etc/mnttab > /dev/null 2>&1
	mount -F ufs -o nologging $lofidev "$rdmnt"
	files=

	# do the actual copy
	copy_files "$list"
	umount -f "$rdmnt"
	rmdir "$rdmnt"

	if [ $ISA = sparc ] ; then
		rlofidev=`echo "$lofidev" | sed -e "s/dev\/lofi/dev\/rlofi/"`
		bb="$ALT_ROOT/platform/$PLATFORM/lib/fs/ufs/bootblk"
		# installboot is not available on all platforms
		dd if=$bb of=$rlofidev bs=1b oseek=1 count=15 conv=sync 2>&1
	fi

	#
	# Check if gzip exists in /usr/bin, so we only try to run gzip
	# on systems that have gzip. Then run gzip out of the patch to
	# pick it up from bfubin or something like that if needed.
	#
	# If compress is set, the individual files in the archive are
	# compressed, and the final compression will accomplish very
	# little.  To save time, we skip the gzip in this case.
	#
	if [ $ISA = i386 ] && [ $compress = no ] && \
	    [ -x $GZIP_CMD ] ; then
		gzip -c "$rdfile" > "${archive}-new"
	else
		cat "$rdfile" > "${archive}-new"
	fi
	
	if [ $? -ne 0 ] ; then
		rm -f "${archive}-new"
	fi
}

#
# The first argument can be:
#
# "both" - create an archive with both 32-bit and 64-bit binaries
# "32-bit" - create an archive with only 32-bit binaries
# "64-bit" - create an archive with only 64-bit binaries
#
function create_isofs
{
	which=$1
	archive=$2

	# should we exclude amd64 binaries?
	if [ "$which" = "32-bit" ]; then
		rdmnt="$rdmnt32"
		errlog="$errlog32"
		list="$list32"
	elif [ "$which" = "64-bit" ]; then
		rdmnt="$rdmnt64"
		errlog="$errlog64"
		list="$list64"
	else
		rdmnt="$rdmnt32"
		errlog="$errlog32"
		list="$list32"
	fi

	# create image directory seed with graft points
	mkdir "$rdmnt"
	files=
	isocmd="mkisofs -quiet -graft-points -dlrDJN -relaxed-filenames"

	if [ $ISA = sparc ] ; then
		bb="$ALT_ROOT/platform/$PLATFORM/lib/fs/hsfs/bootblk"
		isocmd="$isocmd -G \"$bb\""
	fi

	copy_files "$list"
	isocmd="$isocmd \"$rdmnt\""
	rm -f "$errlog"

	#
	# Check if gzip exists in /usr/bin, so we only try to run gzip
	# on systems that have gzip. Then run gzip out of the patch to
	# pick it up from bfubin or something like that if needed.
	#
	# If compress is set, the individual files in the archive are
	# compressed, and the final compression will accomplish very
	# little.  To save time, we skip the gzip in this case.
	#
	mkiso_ret=0

	if [ $ISA = i386 ] &&[ $compress = no ] && [ -x $GZIP_CMD ]
	then
		ksh -c "$isocmd" 2> "$errlog" | \
		    gzip > "${archive}-new"
	else
		ksh -c "$isocmd" 2> "$errlog" > "${archive}-new"
	fi

	if [ $? -ne 0 ]; then
		cat "$errlog"
		rm -f "${archive}-new" 2> /dev/null
		rm -f "$errlog" 2> /dev/null
		return
	fi

	dd_ret=0
	if [ $ISA = sparc ] ; then
		bb="$ALT_ROOT/platform/$PLATFORM/lib/fs/hsfs/bootblk"
		dd if="$bb" of="${archive}-new" bs=1b oseek=1 count=15 \
		    conv=notrunc conv=sync >> "$errlog" 2>&1
		dd_ret=$?
	fi

	if [ -s "$errlog" ] || [ $dd_ret -ne 0 ] ; then
		grep Error: "$errlog" >/dev/null 2>&1
		if [ $? -eq 0 ] || [ $dd_ret -ne 0 ] ; then
			cat "$errlog"
			rm -f "${archive}-new"
		fi
	fi
	rm -f "$errlog"
}

function create_archive
{
	which=$1
	archive=$2
	lofidev=$3

	echo "updating $archive"

	if [ "$format" = "ufs" ]; then
		create_ufs "$which" "$archive" "$lofidev"
	else
		create_isofs "$which" "$archive"
	fi

	# sanity check the archive before moving it into place
	#
	ARCHIVE_SIZE=`ls -l "${archive}-new" 2> /dev/null | nawk '{ print $5 }'`
	if [ $compress = yes ] || [ $ISA = sparc ] ; then
		#
		# 'file' will report "English text" for uncompressed
		# boot_archives.  Checking for that doesn't seem stable,
		# so we just check that the file exists.
		#
		ls "${archive}-new" >/dev/null 2>&1
	else
		#
		# the file type check also establishes that the
		# file exists at all
		#
		LC_MESSAGES=C file "${archive}-new" | grep gzip > /dev/null
	fi

	if [ $? = 1 ] && [ -x $GZIP_CMD ] || [ "$ARCHIVE_SIZE" -lt 10000 ]
	then
		#
		# Two of these functions may be run in parallel.  We
		# need to allow the other to clean up, so we can't
		# exit immediately.  Instead, we set a flag.
		#
		echo "update of $archive failed"
		ERROR=1
	else
		lockfs -f "/$ALT_ROOT" 2>/dev/null
		mv "${archive}-new" "$archive"
		rm -f "$archive.hash"
		digest -a sha1 "$archive" > "$archive.hash"
		lockfs -f "/$ALT_ROOT" 2>/dev/null
	fi

}

function fatal_error
{
	print -u2 $*
	exit 1
}

#
# get filelist
#
if [ ! -f "$ALT_ROOT/boot/solaris/filelist.ramdisk" ] &&
    [ ! -f "$ALT_ROOT/etc/boot/solaris/filelist.ramdisk" ]
then
	print -u2 "Can't find filelist.ramdisk"
	exit 1
fi
filelist=$($EXTRACT_FILELIST $EXTRACT_ARGS \
	/boot/solaris/filelist.ramdisk \
	/etc/boot/solaris/filelist.ramdisk \
		2>/dev/null | sort -u)

#
# We use /tmp/ for scratch space now.  This may be changed later if there
# is insufficient space in /tmp/.
#
rddir="/tmp/create_ramdisk.$$.tmp"
new_rddir=
rm -rf "$rddir"
mkdir "$rddir" || fatal_error "Could not create temporary directory $rddir"

# Clean up upon exit.
trap 'cleanup' EXIT

list32="$rddir/filelist.32"
list64="$rddir/filelist.64"

touch $list32 $list64

#
# This loop creates the 32-bit and 64-bit lists of files.  The 32-bit list
# is written to stdout, which is redirected at the end of the loop.  The
# 64-bit list is appended with each write.
#
cd "/$ALT_ROOT"
find $filelist -print 2>/dev/null | while read path
do
	if [ $SPLIT = no ]; then
		print "$path"
	elif [ -d "$path" ]; then
		if [ $format = ufs ]; then
			size=`ls -lLd "$path" | nawk '
			    {print ($5 % 1024) ? (int($5 / 1024) + 1) * 1024 : $5}'`
			if [ `basename "$path"` != "amd64" ]; then
				(( dirsize32 += size ))
			fi
			(( dirsize64 += size ))
		fi
	else
		case `LC_MESSAGES=C /usr/bin/file -m /dev/null "$path" 2>/dev/null` in
		*ELF\ 64-bit*)
			print "$path" >> "$list64"
			;;
		*ELF\ 32-bit*)
			print "$path"
			;;
		*)
			# put in both lists
			print "$path"
			print "$path" >> "$list64"
		esac
	fi
done >"$list32"

if [ $format = ufs ] ; then
	# calculate image size
	getsize

	# check to see if there is sufficient space in tmpfs 
	#
	tmp_free=`df -b /tmp | tail -1 | awk '{ printf ($2) }'`
	(( tmp_free = tmp_free / 3 ))
	if [ $SPLIT = yes ]; then
		(( tmp_free = tmp_free / 2 ))
	fi

	if [ $total_size -gt $tmp_free  ] ; then
		# assumes we have enough scratch space on $ALT_ROOT
		new_rddir="/$ALT_ROOT/var/tmp/create_ramdisk.$$.tmp"
		rm -rf "$new_rddir"
		mkdir "$new_rddir" || fatal_error \
		    "Could not create temporary directory $new_rddir"

		# Save the file lists
		mv "$list32" "$new_rddir"/
		mv "$list64" "$new_rddir"/
		list32="/$new_rddir/filelist.32"
		list64="/$new_rddir/filelist.64"

		# Remove the old $rddir and set the new value of rddir
		rm -rf "$rddir"
		rddir="$new_rddir"
		new_rddir=
	fi
fi

rdfile32="$rddir/rd.file.32"
rdfile64="$rddir/rd.file.64"
rdmnt32="$rddir/rd.mount.32"
rdmnt64="$rddir/rd.mount.64"
errlog32="$rddir/rd.errlog.32"
errlog64="$rddir/rd.errlog.64"
lofidev32=""
lofidev64=""

if [ $SPLIT = yes ]; then
	#
	# We can't run lofiadm commands in parallel, so we have to do
	# them here.
	#
	if [ "$format" = "ufs" ]; then
		mkfile ${size32}k "$rdfile32"
		lofidev32=`lofiadm -a "$rdfile32"`
		mkfile ${size64}k "$rdfile64"
		lofidev64=`lofiadm -a "$rdfile64"`
	fi
	create_archive "32-bit" "$ALT_ROOT/$BOOT_ARCHIVE" $lofidev32 &
	create_archive "64-bit" "$ALT_ROOT/$BOOT_ARCHIVE_64" $lofidev64
	wait
	if [ "$format" = "ufs" ]; then
		lofiadm -d "$rdfile32"
		lofiadm -d "$rdfile64"
	fi
else
	if [ "$format" = "ufs" ]; then
		mkfile ${total_size}k "$rdfile32"
		lofidev32=`lofiadm -a "$rdfile32"`
	fi
	create_archive "both" "$ALT_ROOT/$BOOT_ARCHIVE" $lofidev32
	[ "$format" = "ufs" ] && lofiadm -d "$rdfile32"
fi
if [ $ERROR = 1 ]; then
	cleanup
	exit 1
fi

#
# For the diskless case, hardlink archive to /boot to make it
# visible via tftp. /boot is lofs mounted under /tftpboot/<hostname>.
# NOTE: this script must work on both client and server.
#
grep "[	 ]/[	 ]*nfs[	 ]" "$ALT_ROOT/etc/vfstab" > /dev/null
if [ $? = 0 ]; then
	rm -f "$ALT_ROOT/boot/boot_archive" "$ALT_ROOT/boot/amd64/boot_archive"
	ln "$ALT_ROOT/$BOOT_ARCHIVE" "$ALT_ROOT/boot/boot_archive"
	if [ $SPLIT = yes ]; then
		ln "$ALT_ROOT/$BOOT_ARCHIVE_64" \
		    "$ALT_ROOT/boot/amd64/boot_archive"
	fi
fi
[ -n "$rddir" ] && rm -rf "$rddir"
