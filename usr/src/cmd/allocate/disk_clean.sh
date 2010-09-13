#! /usr/bin/sh
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
#
# This is a clean script for removable disks
# 
# Following is the syntax for calling the script:
#	scriptname [-s|-f|-i|-I] devicename [-A|-D] username zonename zonepath
#
#    	-s for standard cleanup by a user
# 	-f for forced cleanup by an administrator
# 	-i for boot-time initialization (when the system is booted with -r) 
# 	-I to suppress error/warning messages; the script is run in the '-i'
#	   mode
#
# $1:	devicename - device to be allocated/deallocated, e.g., sr0
#
# $2:	-A if cleanup is for allocation, or -D if cleanup is for deallocation.
#
# $3:	username - run the script as this user, rather than as the caller.
#
# $4:	zonename - zone in which device to be allocated/deallocated
#
# $5:	zonepath - root path of zonename
#
# A clean script for a removable media device should prompt the user to 
# insert correctly labeled media at allocation time, and ensure that the
# media is ejected at deallocation time.
#
# Unless the clean script is being called for boot-time
# initialization, it may communicate with the user via stdin and
# stdout.  To communicate with the user via CDE dialogs, create a
# script or link with the same name, but with ".windowing" appended.
# For example, if the clean script specified in device_allocate is
# /etc/security/xyz_clean, that script must use stdin/stdout.  If a
# script named /etc/security/xyz_clean.windowing exists, it must use
# dialogs.  To present dialogs to the user, the dtksh script
# /etc/security/lib/wdwmsg may be used.
#
# This particular script, disk_clean, will work using stdin/stdout, or
# using dialogs.  A symbolic link disk_clean.windowing points to
# disk_clean.
#
 
# ####################################################
# ################  Local Functions  #################
# ####################################################
 
#
# Set up for windowing and non-windowing messages
#
msg_init()
{
    if [ `basename $0` != `basename $0 .windowing` ]; then
	WINDOWING="yes"
	case $VOLUME_MEDIATYPE in
	  cdrom)   TITLE="CD-ROM";;
	  rmdisk)  TITLE="Removable Disk";;
	  floppy)  TITLE="Floppy";;
	  *)       TITLE="Disk";;
	esac
	
	if [ "$MODE" = "allocate" ]; then
	    TITLE="$TITLE Allocation"
	else
	    TITLE="$TITLE Deallocation"
	fi
    else
	WINDOWING="no"
    fi
}

#
# Display a message for the user.  For windowing, user must press OK button 
# to continue. For non-windowing, no response is required.
#
msg() {
    if [ "$WINDOWING" = "yes" ]; then
	$WDWMSG "$*" "$TITLE" OK
    elif [ "$silent" != "y" ]; then
	echo "$*" > /dev/${MSGDEV}
    fi
}

ok_msg() {
	if [ "$WINDOWING" = "yes" ]; then
		$WDWMSG "$*" "$TITLE" READY
	else
		form=`gettext "Media in %s is ready. Please store safely."`
		printf "${form}\n" $PROG $DEVICE > /dev/{MSGDEV}
	fi
}

error_msg() {
	if [ "$WINDOWING" = "yes" ]; then
		$WDWMSG "$*" "$TITLE" ERROR
	else
		form=`gettext "%s: Error cleaning up device %s."`
		printf "${form}\n" $PROG $DEVICE > /dev/${MSGDEV}
	fi
}

#
# Ask the user an OK/Cancel question.  Return 0 for OK, 1 for Cancel.
#
okcancel() {
    if [ "$WINDOWING" = "yes" ]; then
	$WDWMSG "$*" "$TITLE" OK Cancel
    elif [ "$silent" != "y" ]; then
	get_reply "$* (y to continue, n to cancel) \c" y n
    fi
}

#
# Ask the user an Yes/No question.  Return 0 for Yes, 1 for No
#
yesno() {
    if [ "$WINDOWING" = "yes" ]; then
	$WDWMSG "$*" "$TITLE" Yes No
    elif [ "$silent" != "y" ]; then
	get_reply "$* (y/n) \c" y n
    fi
}

#
# Display an error message, put the device in the error state, and exit.
#
error_exit() {
	if [ "$silent" != "y" ]; then
		msg "$2" "$3" \
		    "\n\nDevice has been placed in allocation error state." \
		    "\nPlease inform system administrator."
	fi
	exit 1
}

#
# get_reply prompt choice ...
#
get_reply() {
	prompt=$1; shift
	while true
	do
		echo $prompt > /dev/tty
		read reply
		i=0
		for choice in $*
		do
			if [ "$choice" = "$reply" ]
			then
				return $i
			else
				i=`expr $i + 1`
			fi
		done
	done
}

#
# Find the first disk slice containing a file system
#
find_fs()
{
	# The list of files in device_maps(4) is in an unspecified order.
	# To speed up the fstyp(1M) scanning below in most cases, perform
	# the search for filesystems as follows:
	# 1) Select only block device files of the form "/dev/dsk/*".
	# 2) Sort the list of files in an order more likely to yield
	#    matches: first the fdisk(1M) partitions ("/dev/dsk/cNtNdNpN")
	#    then the format(1M) slices ("/dev/dsk/cNtNdNsN"), in ascending
	#    numeric order within each group.
	DEVall="`echo $FILES | \
	    /usr/bin/tr ' ' '\n' | \
	    /usr/bin/sed '/^\/dev\/dsk\//!d; s/\([sp]\)\([0-9]*\)$/ \1 \2/;' | \
	    /usr/bin/sort -t ' ' -k 2,2d -k 3,3n | \
	    /usr/bin/tr -d ' '`"
	for DEVn in $DEVall ; do
		fstyp_output="`/usr/sbin/fstyp -a $DEVn 2>&1`"
		if [ $? = 0 ]; then
			FSPATH=$DEVn
			gen_volume_label="`echo "$fstyp_output" | \
			    sed -n '/^gen_volume_label: .\(.*\).$/s//\1/p'`"
			if [ "$gen_volume_label" != "" ]; then
				FSNAME="`echo $gen_volume_label | \
				    /usr/xpg4/bin/tr '[:upper:] ' '[:lower:]_'`"
			fi
			# For consistency, hsfs filesystems detected at
			# /dev/dsk/*p0 are mounted as /dev/dsk/*s2
			FSTYPE=`echo "$fstyp_output" | /usr/bin/head -1`
			if [ "$FSTYPE" = hsfs -a \
			    `/usr/bin/expr $FSPATH : '.*p0'` -gt 0 ]; then
				FSPATH=`echo $FSPATH | /usr/bin/sed 's/p0$/s2/'`
			fi
			return
		fi
	done
}

#
# Find all mountpoints in use for a set of device special files.
# Usage: findmounts devpath ...
#

findmounts() {
	nawk -f - -v vold_root="$VOLD_ROOT" -v devs="$*" /etc/mnttab <<\
	    "ENDOFAWKPGM"
	BEGIN {
		split(devs, devlist, " ");
		for (devN in devlist) {
			dev = devlist[devN];
			realdevlist[dev] = 1;
			sub(/.*\//, "", dev);
			sub(/s[0-9]$/, "", dev);
			if (vold_root != "") {
				vold_dir[vold_root "/dev/dsk/" dev] = 1;
				vold_dir[vold_root "/dev/rdsk/" dev] = 1;
			}
		}
	}

	{
		for (dev in realdevlist) {
			if ($1 == dev) {
				mountpoint = $2;
				print mountpoint;
			}
		}
		for (dev in vold_dir) {
			if (substr($1, 1, length(dev)) == dev) {
				mountpoint = $2;
				print mountpoint;
			}
		}
	}
ENDOFAWKPGM
}

#
# Allocate a device.
# Ask the user to make sure the disk is properly labeled.
# Ask if the disk should be mounted.
#
do_allocate()
{
	if [ $VOLUME_MEDIATYPE = floppy ]; then
		# Determine if media is in drive
		eject_msg="`eject -q $DEVFILE 2>&1`"
		eject_status="$?"
		case $eject_status in
		1) # Media is not in drive
			okcancel "Insert disk in $DEVICE."
			if [ $? != 0 ]; then
				exit 0
			fi;;
		3) # Error 
			error_exit $DEVICE \
			    "Error checking for media in drive.";;
		esac
	else
		okcancel "Insert disk in $DEVICE."
		if [ $? != 0 ]; then
			exit 0
		fi
	fi
    
	yesno "Do you want $DEVICE mounted?"
	if [ $? != 0 ]; then
		exit 0
	fi

	if [ $VOLUME_MEDIATYPE = cdrom -o $VOLUME_MEDIATYPE = rmdisk ]; then
		# Get the device path and volume name of a partition
		find_fs
		if [ "$FSPATH" != "" ]; then
			VOLUME_PATH=$FSPATH	
		fi
		if [ "$FSNAME" != "" ]; then
			VOLUME_NAME=$FSNAME
		fi
	fi
	VOLUME_ACTION=insert

	# Give ourself write permission on device file so file system gets
	# mounted read/write if possible.
	# rmmount only cares about permissions not user...
	chown $VOLUME_USER $VOLUME_PATH
	chmod 700 $VOLUME_PATH

	# Do the actual mount.  VOLUME_* environment variables are inputs to
	# rmmount.
	rmmount_msg="`/usr/sbin/rmmount 2>&1`"
	rmmount_status="$?"
	if [ $rmmount_status -eq 0 ]; then
		EXIT_STATUS=$CLEAN_MOUNT
	elif [ $rmmount_status -gt 0 -a $VOLUME_MEDIATYPE != cdrom ]; then
		# Try again in readonly mode. cdrom is always mounted ro, so
		# no need to try again.
		echo "Read-write mount of $DEVICE failed. Mounting read-only."
		VOLUME_ACTION=remount; export VOLUME_ACTION
		VOLUME_MOUNT_MODE=ro; export VOLUME_MOUNT_MODE
		`/usr/sbin/rmmount`
		if [ $? -eq 0 ]; then
			EXIT_STATUS=$CLEAN_MOUNT
		fi
	fi

	# Set permissions on directory used by vold, sdtvolcheck, etc.
	if [ -d /tmp/.removable ]; then
		chown root /tmp/.removable
		chmod 777 /tmp/.removable
	fi
}


do_deallocate()
{
	if [ $VOLUME_MEDIATYPE = cdrom -o $VOLUME_MEDIATYPE = rmdisk ]; then
		if [ -h /$VOLUME_MEDIATYPE/$DEVICE ]; then
			# Get the device path and volume name of a partition
			VOLUME_PATH=`ls -l /$VOLUME_MEDIATYPE/$DEVICE|\
			    cut -d '>' -f2`
			VOLUME_DEVICE=`mount -p|grep $VOLUME_PATH|\
			    cut -d ' ' -f1`
		fi
	fi

	if [ -d "$VOLUME_PATH" ]; then
		VOLUME_ACTION=eject
		# Do the actual unmount.
		# VOLUME_* environment variables are inputs to rmmount.
		rmmount_msg="`/usr/sbin/rmmount 2>&1`"
		rmmount_status="$?"

		# Remove symbolic links to mount point
		for name in /$VOLUME_MEDIATYPE/*; do
			if [ -h $name ]; then
				target=`ls -l $name | awk '{ print $NF; }'`
				target_dir=`dirname $target`
				target_device=`echo $target_dir | \
				    sed -e 's/^.*-\(.*\)$/\1/'`
				if [ "$target_device" = "$DEVICE" ]; then
					rm -f $name
				fi
			fi
		done
	else
		rmmount_status=0
	fi

	case $rmmount_status in
	1) # still mounted
		error_exit $DEVICE "Error unmounting $DEVICE" "$rmmount_msg";;
	0) # not mounted
		# Eject the media
		if [ "$FLAG" = "f" ] ; then
			eject_msg="`eject -f $DEVICE 2>&1`"
		else
			eject_msg="`eject $DEVICE 2>&1`"
		fi
		eject_status="$?"
		case $eject_status in
		0|1|4) # Media has been ejected
			case $VOLUME_MEDIATYPE in
			floppy|cdrom|rmdisk)
				msg "Please remove the disk from $DEVICE.";;
			esac;;
		3) # Media didn't eject
			msg $DEVICE "Error ejecting disk from $DEVICE" \
			    "$eject_msg";;
		esac
	esac
}

#
# Reclaim a device
#
do_init()
{
	eject_msg="`eject -f $DEVICE 2>&1`"
	eject_status="$?"

	case $eject_status in
	0) # Media has been ejected 
		if [ "$silent" != "y" ]; then
			ok_msg
		fi
		exit 0;;
	1) # Media not ejected
		if [ "$silent" != "y" ]; then
			error_msg
		fi
		exit 0;;
	3) # Error 
		if [ "$silent" != "y" ]; then
			error_msg
		fi
		msg $DEVICE "Error ejecting disk from $DEVICE" \
		"$eject_msg"
		exit 2;;
	esac
}


# ####################################################
# ################ Begin main program ################
# ####################################################

trap "" INT TERM QUIT TSTP ABRT

PATH="/usr/bin:/usr/sbin"
MODE="allocate"
SILENT=n
WDWMSG="/etc/security/lib/wdwmsg"
VOLUME_ZONE_PATH="/"
USAGE="Usage: disk_clean [-s|-f|-i|-I] devicename -[A|D] [username] [zonename] [zonepath]"
EXIT_STATUS=0
CLEAN_MOUNT=4
MACH=`uname -p`
FLAG=i
#
# Parse the command line arguments
#
while getopts ifsI c
do
	case $c in
	i)
		FLAG=$c;;
	f)
		FLAG=$c;;
	s)
		FLAG=$c;;
	I)
		FLAG=i
		silent=y;;
	\?)
		echo $USAGE
		exit 1;;
      esac
done

shift `expr $OPTIND - 1`

DEVICE=$1
MODE="deallocate"
if [ "$2" = "-A" ]; then
	MODE="allocate"
elif [ "$2" = "-D" ]; then
	MODE="deallocate"
fi

#get the device_maps information
MAP=`/usr/sbin/list_devices -s -l $DEVICE`
FILES=`echo $MAP | cut -f4 -d:`	# e.g., /dev/dsk/c0t6d0s0 /dev/dsk/c0t6d0s1 ...
DEVFILE=`echo $FILES | cut -f1 -d" "` 		# e.g., "/dev/dsk/c0t6d0s0"

# Set VOLUME_ variables that are inputs to rmmount

VOLUME_DEVICE=`echo $FILES | cut -f2 -d" "` 	# e.g., "/dev/dsk/c0t6d0s1"
MEDIATYPE=`echo $MAP | cut -f3 -d: | cut -f2 -d" "`
					 	# e.g., "cdrom" or "floppy"
if [ "$MEDIATYPE" = "sr" ]; then
	VOLUME_MEDIATYPE="cdrom"
elif [ "$MEDIATYPE" = "fd" ]; then
	VOLUME_MEDIATYPE="floppy"
elif [ "$MEDIATYPE" = "rmdisk" ]; then
	VOLUME_MEDIATYPE="rmdisk"
fi

VOLUME_PATH=$DEVFILE				# e.g., "/dev/dsk/c0t6d0s0"
if [ "$MACH" = "i386" ] && [ "$MEDIATYPE" = "rmdisk" ]; then
	VOLUME_PATH=`echo $DEVFILE | sed -e 's/s0/p0/'`
fi

SYMDEV=`echo $DEVICE | sed -e 's/_//'`		# e.g., "cdrom" or "floppy"
SYMNUM=`echo $SYMDEV | sed -e 's/[a-z]*//g'`
SYMDEV=`echo $SYMDEV | sed -e 's/[0-9]*//g'`
if [ "$SYMDEV" = "sr" ]; then
	VOLUME_SYMDEV="cdrom"$SYMNUM
elif [ "$SYMDEV" = "fd" ]; then
	VOLUME_SYMDEV="floppy"$SYMNUM
elif [ "$SYMDEV" = "rmdisk" ]; then
	VOLUME_SYMDEV="rmdisk"$SYMNUM
else
	VOLUME_SYMDEV=$SYMDEV$SYMNUM
fi

VOLUME_ZONE_NAME=$4

VOLUME_ZONE_PATH=$5

if [ "$MODE" = "allocate" ]; then
	if [ -n "$3" ]; then			# e.g., "joeuser"
		VOLUME_USER=$3
	else
		VOLUME_USER=`/usr/xpg4/bin/id -u -nr`
	fi
else
	# If there's a directory for the device under /<mediatype>, get the 
	# user name from there, to use in cleaning up that directory. Otherwise,
	# the user name isn't actually used in deallocation.
	if [ -d ${VOLUME_ZONE_PATH}/${VOLUME_MEDIATYPE}/*-${DEVICE} ]; then
		VOLUME_USER=`ls -ld ${VOLUME_ZONE_PATH}/${VOLUME_MEDIATYPE}/*-${DEVICE} | awk '/^d/{print $3}'`
	else
		if [ -n "$3" ]; then
			VOLUME_USER=$3
		else
			VOLUME_USER=`/usr/xpg4/bin/id -u -nr`
		fi
	fi
fi    

VOLUME_NAME=unnamed_${VOLUME_MEDIATYPE}
					# e.g., "joeuser-cdrom0/unnamed_cdrom"

if [ "$VOLUME_MEDIATYPE" = "rmdisk" ]; then
	VOLUME_PCFS_ID=1
else
	VOLUME_PCFS_ID=
fi

export VOLUME_ACTION VOLUME_DEVICE VOLUME_MEDIATYPE VOLUME_NAME VOLUME_PCFS_ID
export VOLUME_PATH VOLUME_SYMDEV VOLUME_USER VOLUME_ZONE_NAME VOLUME_ZONE_PATH

USERDIR=${VOLUME_USER}-${DEVICE}	# e.g., "joeusr-cdrom0"

msg_init

if [ "$MODE" = "allocate" ]; then
	MSGDEV=tty
  	do_allocate
else
    if [ "$FLAG" = "i" ] ; then
	MSGDEV=console
	do_init
    else
	MSGDEV=tty
	do_deallocate
    fi
fi

exit $EXIT_STATUS
