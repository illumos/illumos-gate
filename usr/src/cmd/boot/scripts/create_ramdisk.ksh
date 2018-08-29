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
# Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
#

ALT_ROOT=
EXTRACT_ARGS=
FORMAT=
format_set=0
compress=yes
dirsize=0

usage() {
	cat <<- EOM
This utility is a component of the bootadm(1M) implementation and it is not
recommended for stand-alone use. Please use bootadm(1M) instead.

Usage: ${0##*/}: [-R <root>] [-p <platform>] [ -f <format> ] [--nocompress]
where <platform> is one of i86pc, sun4u or sun4v
  and <format> is one of ufs, ufs-nocompress or cpio
	EOM
	exit
}

# default platform is what we're running on
PLATFORM=`uname -m`

export PATH=/usr/sbin:/usr/bin:/sbin
export GZIP_CMD=/usr/bin/gzip
export CPIO_CMD=/usr/bin/cpio

EXTRACT_FILELIST="/boot/solaris/bin/extract_boot_filelist"

#
# Parse options
#
while [ -n "$1" ]; do
        case $1 in
	-f)	shift
		FORMAT="$1"
		format_set=1
		;;
	-n|--nocompress) compress=no
		;;
	-p)	shift
		PLATFORM="$1"
		EXTRACT_ARGS="${EXTRACT_ARGS} -p ${PLATFORM}"
		;;
        -R)	shift
		ALT_ROOT="$1"
		if [ "$ALT_ROOT" != "/" ]; then
			echo "Creating boot_archive for $ALT_ROOT"
			EXTRACT_ARGS="${EXTRACT_ARGS} -R ${ALT_ROOT}"
			EXTRACT_FILELIST="${ALT_ROOT}${EXTRACT_FILELIST}"
		fi
		;;
        *)      usage
		;;
        esac
	shift
done

shift `expr $OPTIND - 1`

if [ $# -eq 1 ]; then
	ALT_ROOT="$1"
	echo "Creating boot_archive for $ALT_ROOT"
fi

if [ -z "$FORMAT" ]; then
	if [ -n "$ALT_ROOT" ]; then
		SVCCFG_DTD=/$ALT_ROOT/usr/share/lib/xml/dtd/service_bundle.dtd.1
		SVCCFG_REPOSITORY=/$ALT_ROOT/etc/svc/repository.db
		export SVCCFG_DTD SVCCFG_REPOSITORY
	fi
	FORMAT=`svccfg -s system/boot-archive listprop config/format \
	    | awk '{print $3}'`
fi

if [ $format_set -eq 0 -a "$FORMAT" = hsfs ]; then
	if /sbin/bootadm update-archive -R ${ALT_ROOT:-/} -f -L -F hsfs; then
		exit 0
	else
		echo "Failed to create HSFS archive, falling back."
	fi
fi

[[ "$FORMAT" =~ ^(cpio|ufs|ufs-nocompress)$ ]] || FORMAT=ufs

case $PLATFORM in
i386|i86pc)	PLATFORM=i86pc
		ISA=i386
		ARCH64=amd64
		BOOT_ARCHIVE_SUFFIX=$ARCH64/boot_archive
		;;
sun4u|sun4v)	ISA=sparc
		ARCH64=sparcv9
		BOOT_ARCHIVE_SUFFIX=boot_archive
		compress=no
		;;
*)		usage
		;;
esac

BOOT_ARCHIVE=platform/$PLATFORM/$BOOT_ARCHIVE_SUFFIX

function fatal_error
{
	print -u2 $*
	exit 1
}

[ -x $GZIP_CMD ] || compress=no

case $FORMAT in
cpio)		[ -x $CPIO_CMD ] || FORMAT=ufs ;;
ufs-nocompress)	FORMAT=ufs; compress=no ;;
ufs)		;;
esac

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
	typeset listfile="$1"

	#
	# If compress is set, the files are gzip'd and put in the correct
	# location in the loop.  Nothing is printed, so the pipe and cpio
	# at the end is a nop.
	#
	# If compress is not set, the file names are printed, which causes
	# the cpio at the end to do the copy.
	#
	while read path; do
		if [ $compress = yes ]; then
			dir="${path%/*}"
			[ -d "$rdmnt/$dir" ] || mkdir -p "$rdmnt/$dir"
			$GZIP_CMD -c "$path" > "$rdmnt/$path"
		else
			print "$path"
		fi
	done <"$listfile" | cpio -pdum "$rdmnt" 2>/dev/null

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

function ufs_cleanup
{
	umount -f "$rdmnt" 2>/dev/null
	lofiadm -d "$rdfile" 2>/dev/null
	[ -n "$rddir" ] && rm -fr "$rddir" 2> /dev/null
	[ -n "$new_rddir" ] && rm -fr "$new_rddir" 2>/dev/null
}

function ufs_getsize
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
	size=$(cat "$list" | xargs -I {} ls -lLd "{}" 2> /dev/null |
		nawk '{t += ($5 % 1024) ? (int($5 / 1024) + 1) * 1024 : $5}
		END {print int(t * 1.10 / 1024)}')
	(( size += dirsize ))
	(( total_size = size ))
	# If compression is enabled, then each file within the archive will
	# be individually compressed. The compression ratio is around 60%
	# across the archive so make the image smaller.
	[ $compress = yes ] && (( total_size = total_size / 2 ))
}

function create_ufs_archive
{
	typeset archive="$ALT_ROOT/$BOOT_ARCHIVE"

	[ "$compress" = yes ] && \
	    echo "updating $archive (UFS)" || \
	    echo "updating $archive (UFS-nocompress)"

	#
	# We use /tmp/ for scratch space now.  This will be changed later to
	# $ALT_ROOT/var/tmp if there is insufficient space in /tmp/.
	#
	rddir="/tmp/create_ramdisk.$$.tmp"
	new_rddir=
	rm -rf "$rddir"
	mkdir "$rddir" || fatal_error "Could not create directory $rddir"

	# Clean up upon exit.
	trap 'ufs_cleanup' EXIT

	list="$rddir/filelist"

	cd "/$ALT_ROOT" || fatal_error "Cannot chdir to $ALT_ROOT"
	find $filelist -print 2>/dev/null | while read path; do
		if [ -d "$path" ]; then
			size=`ls -lLd "$path" | nawk '
		    {print ($5 % 1024) ? (int($5 / 1024) + 1) * 1024 : $5}'`
			(( dirsize += size / 1024 ))
		else
			print "$path"
		fi
	done >"$list"

	# calculate image size
	ufs_getsize

	# check to see if there is sufficient space in tmpfs
	#
	tmp_free=`df -b /tmp | tail -1 | awk '{ print $2 }'`
	(( tmp_free = tmp_free / 3 ))

	if [ $total_size -gt $tmp_free ] ; then
		echo "Insufficient space in /tmp, using $ALT_ROOT/var/tmp"
		# assumes we have enough scratch space on $ALT_ROOT
		new_rddir="/$ALT_ROOT/var/tmp/create_ramdisk.$$.tmp"
		rm -rf "$new_rddir"
		mkdir "$new_rddir" || fatal_error \
		    "Could not create temporary directory $new_rddir"

		# Save the file lists
		mv "$list" "$new_rddir"/
		list="/$new_rddir/filelist"

		# Remove the old $rddir and set the new value of rddir
		rm -rf "$rddir"
		rddir="$new_rddir"
		new_rddir=
	fi

	rdfile="$rddir/rd.file"
	rdmnt="$rddir/rd.mount"
	errlog="$rddir/rd.errlog"
	lofidev=""

	mkfile ${total_size}k "$rdfile" || \
	    fatal_error "Could not create backing file"
	lofidev=`lofiadm -a "$rdfile"` || \
	    fatal_error "Could not create lofi device"

	NOINUSE_CHECK=1 newfs -m 0 $lofidev < /dev/null 2> /dev/null
	mkdir "$rdmnt"
	mount -F mntfs mnttab /etc/mnttab > /dev/null 2>&1
	mount -F ufs -o nologging $lofidev "$rdmnt"
	rm -rf "$rdmnt/lost+found"

	# do the actual copy
	copy_files "$list"
	umount -f "$rdmnt"
	rmdir "$rdmnt"

	if [ $ISA = sparc ] ; then
		rlofidev="${lofidev/lofi/rlofi}"
		bb="/$ALT_ROOT/platform/$PLATFORM/lib/fs/ufs/bootblk"
		# installboot is not available on all platforms
		dd if=$bb of=$rlofidev bs=1b oseek=1 count=15 conv=sync 2>&1
	fi

	lofiadm -d "$rdfile"

	#
	# Check if gzip exists in /usr/bin, so we only try to run gzip
	# on systems that have gzip. Then run gzip out of the patch to
	# pick it up from bfubin or something like that if needed.
	#
	# If compress is set, the individual files in the archive are
	# compressed, and the final compression will accomplish very
	# little.  To save time, we skip the gzip in this case.
	#
	if [ $ISA = i386 ] && [ $compress = no ] && [ -x $GZIP_CMD ] ; then
		$GZIP_CMD -c "$rdfile" > "${archive}-new"
	else
		cat "$rdfile" > "${archive}-new"
	fi

	if [ $? -ne 0 ] ; then
		rm -f "${archive}-new"
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
		fatal_error "update of $archive failed"
	else
		lockfs -f "/$ALT_ROOT" 2>/dev/null
		rm -f "$archive.hash"
		mv "${archive}-new" "$archive"
		digest -a sha1 "$rdfile" > "$archive.hash"
		lockfs -f "/$ALT_ROOT" 2>/dev/null
	fi
	[ -n "$rddir" ] && rm -rf "$rddir"
}

function cpio_cleanup
{
	[ -f "/$ALT_ROOT/$tarchive" ] && rm -f "/$ALT_ROOT/$tarchive"
	[ -f "/$ALT_ROOT/$tarchive.cpio" ] && rm -f "/$ALT_ROOT/$tarchive.cpio"
	[ -f "/$ALT_ROOT/$tarchive.hash" ] && rm -f "/$ALT_ROOT/$tarchive.hash"
}

function create_cpio_archive
{
	typeset archive="$ALT_ROOT/$BOOT_ARCHIVE"

	echo "updating $archive (CPIO)"

	tarchive="$archive.$$.new"

	# Clean up upon exit.
	trap 'cpio_cleanup' EXIT

	cd "/$ALT_ROOT" || fatal_error "Cannot chdir to $ALT_ROOT"

	touch "$tarchive" \
	    || fatal_error "Cannot create temporary archive $tarchive"

	find $filelist 2>/dev/null | cpio -qo -H odc > "$tarchive.cpio" \
	    || fatal_error "Problem creating archive"

	[ -x /usr/bin/digest ] \
	    && /usr/bin/digest -a sha1 "$tarchive.cpio" \
	    > "$tarchive.hash"

	if [ -x "$GZIP_CMD" ]; then
		$GZIP_CMD -c "$tarchive.cpio" > "$tarchive"
		rm -f "$tarchive.cpio"
	else
		mv "$tarchive.cpio" "$tarchive"
	fi

	# Move new archive into place
	[ -f "$archive.hash" ] && rm -f "$archive.hash"
	mv "$tarchive" "$archive"
	[ $? -eq 0 -a  -f "$tarchive.hash" ] \
	    && mv "$tarchive.hash" "$archive.hash"
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

# Now that we have the list of files, we can create the archive.

case "$FORMAT" in
	cpio)	create_cpio_archive ;;
	ufs)	create_ufs_archive ;;
	*)	print -u2 "Unknown boot archive format, $FORMAT"
		exit 1
		;;
esac

#
# For the diskless case, hardlink archive to /boot to make it
# visible via tftp. /boot is lofs mounted under /tftpboot/<hostname>.
# NOTE: this script must work on both client and server.
#
grep "[	 ]/[	 ]*nfs[	 ]" "$ALT_ROOT/etc/vfstab" > /dev/null
if [ $? = 0 ]; then
	rm -f "$ALT_ROOT/boot/$BOOT_ARCHIVE_SUFFIX"
	mkdir -p "$ALT_ROOT/boot/`dirname $BOOT_ARCHIVE_SUFFIX`"
	ln "$ALT_ROOT/$BOOT_ARCHIVE" "$ALT_ROOT/boot/$BOOT_ARCHIVE_SUFFIX"
fi
