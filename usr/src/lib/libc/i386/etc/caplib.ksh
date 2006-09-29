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
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This script is called by flarcreate.sh
#
# Unmount all hwcap libraries (like /usr/lib/libc/libc_hwcap2.so.1)
# and store commands needed to remount them in preexit/remount_hwcap.xxxx
# scripts, which remounts them in the preexit phase.
#  

if [ -z "$FLASH_PID" ]; then
	echo "$0: ERROR: FLASH_PID not set in execution environment, exiting..."
	exit 1 
fi
if [ -z "$FLASH_DIR" ]; then
	echo "$0: ERROR: FLASH_DIR not set in execution environment, exiting..."
	exit 1 
fi

CHMOD=/usr/bin/chmod
ELFDUMP=/usr/ccs/bin/elfdump
MOUNT=/usr/sbin/mount
UMOUNT=/usr/sbin/umount
EGREP=/usr/bin/egrep
SED=/usr/bin/sed
CMD_LIST="$CHMOD $ELFDUMP $MOUNT $UMOUNT $EGREP $SED"

for cmd in $CMD_LIST
do
    if [ ! -x $cmd ]; then
	echo "$0: ERROR: $cmd not found or not executable, exiting..."
	exit 1
    fi
done

#
# Fill "LIBS" with a list of mounted libraries in the form:
# 	MOUNTPOUNT:FILE
# e.g.:
#	/lib/libc.so.1:/usr/lib/libc/libc_hwcap2.so.1
#
LIBS=`$MOUNT | $EGREP "^/lib|^/usr/lib" | \
    $SED -e 's:^\(/[^ ]*\) on \([^ ]*\).*$:\1@\2:'`

if [ ! "$LIBS" ]; then
	exit 0
fi

REMOUNT_DIR=${FLASH_DIR}/preexit
REMOUNT=${REMOUNT_DIR}/remount_hwcap.${FLASH_PID}

#
# Create the flash preexit script directory for the remount scripts if it
# doesn't already exist.
#
if [ ! -d $REMOUNT_DIR ]; then
	umask 077
	/usr/bin/mkdir $REMOUNT_DIR
	if [ $? -ne 0 ]; then
		echo "$0: ERROR: could not mkdir $REMOUNT_DIR, exiting..."
		exit 1
	fi
fi

#
# If an old remount script by this name exists, delete it
#
if [ -f $REMOUNT ]; then
	/bin/rm -f $REMOUNT
fi

umask 477

cat > $REMOUNT << EOF
#!/bin/sh
if [ \"\$FLASH_PID\" != \"$FLASH_PID\" ]; then
	/bin/rm -f $REMOUNT
	exit 0
fi
EOF

if [ $? -ne 0 ]; then
	echo "$0: ERROR: could not create $REMOUNT, exiting..."
	exit 1
fi

#
# Now process each of the libraries that are mounted.  For each, find out if
# it's a hwcap library; if it is, unmount it and write instructions to the
# preexit script as to how to remount it.
# 
for entry in $LIBS
do
	echo $entry | IFS=@ read MOUNTPOINT MOUNTLIB
	CAPLIB=`$ELFDUMP -H $MOUNTLIB`
	if [ \( $? -eq 0 \) -a \( -n "$CAPLIB" \) ]; then
		$UMOUNT $MOUNTPOINT || $UMOUNT -f $MOUNTPOINT || \
		    { echo "$0: ERROR: Could not unmount" \
			  "$MOUNTPOINT, exiting..."; \
		      /bin/sh $REMOUNT; /bin/rm -f $REMOUNT; exit 1; }

		echo $MOUNTLIB | $EGREP -s :
		if [ $? -eq 0 ]; then
			MOUNTOPTS="-O"
		else
			MOUNTOPTS="-O -F lofs"
		fi
		echo "$MOUNT $MOUNTOPTS $MOUNTLIB $MOUNTPOINT" >> $REMOUNT
	fi
done

#
# Write final cleanup instructions to the flash preexit remount script and make
# it executable.
#
echo "/bin/rm -f $REMOUNT" >> $REMOUNT
echo "exit 0" >> $REMOUNT
$CHMOD 0500 $REMOUNT
exit 0
