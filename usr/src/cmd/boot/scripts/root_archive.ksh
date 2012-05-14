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

# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.

# utility to pack and unpack a boot/root archive
# both ufs and hsfs (iso9660) format archives are unpacked
# only ufs archives are generated
#
# usage: pack   <archive> <root>
#        unpack <archive> <root>
#
#   Where <root> is the directory to unpack to and will be cleaned out
#   if it exists.
#

usage()
{
	printf "usage: root_archive pack <archive> <root>\n"
	printf "       root_archive unpack <archive> <root>\n"
	exit 1
}

cleanup()
{
	if [ -d $MNT ] ; then
		umount $MNT 2> /dev/null
		rmdir $MNT
	fi

	lofiadm -d "$TMR" 2>/dev/null
        if [ "$REALTHING" != true ] ; then
		rm -f "$TMR"
	fi
	rm -f "$TMR.gz"
	rm -f /tmp/flist$$
}

do_unpack()
{
	(
		cd $MNT
		find . -print | cpio -pdum "$UNPACKED_ROOT" 2> /dev/null
	)
	# increase the chances the unmount will succeed
	umount -f $MNT
}

unpack()
{
	MR=$1
	if [ ! -f "$MR" ] ; then
		printf "$MR: not found\n"
		usage
	fi

	if [ `uname -i` = i86pc ] ; then
		gzcat "$MR" > $TMR
	else
		REALTHING=true ; export REALTHING
		TMR="$MR"
	fi

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
	if [ "$REALTHING" != true ] ; then
		rm $TMR
	fi
}

compress()
{
	SRC=$1
	DST=$2

	(
		cd $SRC
		filelist=`find .`

		for file in $filelist ; do

			file=`echo $file | sed s#^./##`

			# copy all files over to preserve hard links
			#
			echo $file | cpio -pdum $DST 2> /dev/null

			if [ -f $file ] && [ -s $file ] && [ ! -h $file ] ; then
				fiocompress -mc $file $DST/$file &
			fi

		done

		wait `pgrep fiocompress`

		# now re-copy a couple of uncompressed files

		if [ -d "$SRC/platform/i86pc" ] ; then
			find `cat boot/solaris/filelist.ramdisk` -type file \
			    -print 2> /dev/null > /tmp/flist$$
			find usr/kernel -type file -print 2> /dev/null \
			    >> /tmp/flist$$
			# some of the files are replaced with links into
			# tmp/root on the miniroot, so find the backing files
			# from there as well and add them to the list ti
			# be copied uncompressed
			(
				cd $SRC/tmp/root
				find `cat ../../boot/solaris/filelist.ramdisk` \
				    -type file -print 2> /dev/null | \
				    sed 's#^#tmp/root/#' >> /tmp/flist$$
			)
			flist=`cat /tmp/flist$$`
			(
				cd $DST
				rm -f $flist
			)
			for file in $flist ; do
				echo $file | cpio -pdum $DST 2> /dev/null
			done
		else
			find kernel platform -name unix | \
			    cpio -pdum $DST 2> /dev/null
			find kernel platform -name genunix | cpio -pdum $DST \
			    2> /dev/null
			find kernel platform -name platmod | cpio -pdum $DST \
			    2> /dev/null
			find `find kernel platform -name cpu` | \
			    cpio -pdum $DST 2> /dev/null
			find `find kernel platform -name kmdb\*` | \
				cpio -pdum $DST 2> /dev/null
			find kernel/misc/sparcv9/ctf kernel/fs/sparcv9/dcfs \
			    etc/system etc/name_to_major etc/path_to_inst \
			    etc/name_to_sysnum  etc/driver_aliases \
			    etc/driver_classes etc/minor_perm | \
			    cpio -pdum $DST 2> /dev/null
		fi
	)
}

root_is_ramdisk()
{
	grep -v "set root_is_ramdisk=" "$UNPACKED_ROOT"/etc/system | \
	    grep -v "set ramdisk_size=" > /tmp/system.$$
	cat /tmp/system.$$ > "$UNPACKED_ROOT"/etc/system
	rm /tmp/system.$$

	echo set root_is_ramdisk=1 >> "$UNPACKED_ROOT"/etc/system
	echo set ramdisk_size=$1 >> "$UNPACKED_ROOT"/etc/system
}

pack()
{
	MR="$1"
	[ -d "$UNPACKED_ROOT" ] || usage

	# always compress if fiocompress exists
	#
	if [ -x /usr/sbin/fiocompress ] ; then
		COMPRESS=true
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
	#
	# if the operation in turn is compressing the files the amount
	# of typical shrinkage is used to come up with a useful archive
	# size
	size=$(find "$UNPACKED_ROOT" -ls | nawk '
	    {t += ($7 % 1024) ? (int($7 / 1024) + 1) * 1024 : $7}
	    END {print int(t * 1.10 / 1024)}')
	if [ "$COMPRESS" = true ] ; then
		size=`echo $size | nawk '{s = $1} END {print int(s * 0.6)}'`
	fi

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

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		root_is_ramdisk $size
	fi

	(
		cd "$UNPACKED_ROOT"
		if [ "$COMPRESS" = true ] ; then
			compress . $MNT
		else
			find . -print | cpio -pdum $MNT 2> /dev/null
		fi
	)
	lockfs -f $MNT
	umount $MNT
	rmdir $MNT

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		"$UNPACKED_ROOT/usr/sbin/installboot" \
		    "$UNPACKED_ROOT/platform/sun4u/lib/fs/ufs/bootblk" \
		    $RLOFIDEV
	fi

	lofiadm -d $LOFIDEV
	LOFIDEV=

	rm -f "$TMR.gz"

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		mv "$TMR" "$MR"
	else
		gzip -f "$TMR"
		mv "$TMR.gz" "$MR"
	fi

	chmod a+r "$MR"
}

strip_amd64()
{
	find "$UNPACKED_ROOT" -name amd64 -type directory | xargs rm -rf
}

# main
#

EXTRA_SPACE=0
STRIP_AMD64=
COMPRESS=

PATH=/usr/sbin:/usr/bin:/opt/sfw/bin ; export PATH

while getopts s:6c opt ; do
	case $opt in
	s)	EXTRA_SPACE="$OPTARG"
		;;
	6)	STRIP_AMD64=false
		;;
	c)	COMPRESS=true
		;;
	*)	usage
		;;
	esac
done
shift `expr $OPTIND - 1`

[ $# == 3 ] || usage

UNPACKED_ROOT="$3"
BASE="`pwd`"
MNT=/tmp/mnt$$
TMR=/tmp/mr$$
LOFIDEV=
MR="$2"

# sanity check
[ "$UNPACKED_ROOT" != "/" ] || usage

if [ "`dirname $MR`" = . ] ; then
	MR="$BASE/$MR"
fi
if [ "`dirname $UNPACKED_ROOT`" = . ] ; then
	UNPACKED_ROOT="$BASE/$UNPACKED_ROOT"
fi

trap cleanup EXIT

# always unpack into a fresh root
case $1 in
	unpack)
		rm -rf "$UNPACKED_ROOT"
		mkdir -p "$UNPACKED_ROOT"
		;;
esac
[ -d "$UNPACKED_ROOT" ] || usage

case $1 in
	pack)	pack "$MR"
		;;
	unpack)	unpack "$MR"
		;;
	*)	usage
		;;
esac
