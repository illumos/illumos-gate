#!/bin/ksh93 -p
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# mkbootmedia - create bootable Solaris ISO image
#

readonly PROG=$0
MKISOFS=/usr/bin/mkisofs
ELTORITO=boot/grub/stage2_eltorito	# relative to $MEDIA_ROOT
SPARCBOOT=boot/hsfs.bootblock
CAT=/usr/bin/cat
CP=/usr/bin/cp
RM=/usr/bin/rm
UNAME=/usr/bin/uname
MACH=`$UNAME -p`
BOOTBLOCK=
GREP=/usr/bin/grep

# for gettext
TEXTDOMAIN=SUNW_OST_OSCMD
export TEXTDOMAIN


function usage
{
	gettext "Usage:\n${PROG##*/} [-v] [-l <label>] <media-root> <iso>\n"
	gettext "Options:\n  -l <label>\n        Label/volume name of the ISO image.\n"
	gettext "  -v\n        Verbose.  Multiple -v options increase verbosity.\n"
	echo;
}


#
# Main
#
LABEL=
VERBOSITY=0

while getopts ':l:v' opt
do
	case $opt in
	l)	LABEL=$OPTARG
		;;
	v)	(( VERBOSITY += 1 ))
		;;
	:)	gettext "Option -$OPTARG missing argument.\n"
		usage
		exit 1
		;;
	*)	gettext "Option -$OPTARG invalid.\n"
		usage
		exit 2
		;;
	esac
done
shift 'OPTIND - 1'

if (( $# != 2 ))
then
	usage
	exit 1
fi

MEDIA_ROOT=$1
ISOIMAGE=$2

if [ ! -z `echo $ISOIMAGE | $GREP "^/tmp"` ]; then
        gettext "ISO images will not be created on /tmp.\nPlease choose a different output location.\n"
	exit 3
fi

# Verify $MEDIA_ROOT is a Solaris install media (Solaris 10 Update 1 or later)
if [[ ! -d $(echo "$MEDIA_ROOT"/Solaris*/Tools/Boot) ]]; then
	gettext "$MEDIA_ROOT is not Solaris install media.\n"
	exit 1
fi

# If no label specified use the Solaris_* version under $MEDIA_ROOT
if [[ -z "$LABEL" ]]; then
	LABEL=$(echo "$MEDIA_ROOT"/Solaris*)
	LABEL=${LABEL##*/}
fi

# If $ISOIMAGE exists, verify it's writable.
if [[ -e "$ISOIMAGE" && ! -w "$ISOIMAGE" ]]; then
	gettext "$ISOIMAGE exists but is not writable.\n"
	exit 1
fi

# If we're on an x86/x64 system, we need to have the El Torito file
# modified with some boot information (-boot-info-table option).
# If the image isn't writable, we can't continue
# UltraSPARC systems (sun4u, sun4v etc) don't use El Torito
if [[ "$MACH" = "i386" && ! -w "$MEDIA_ROOT/$ELTORITO" ]]; then
	gettext "$MEDIA_ROOT/$ELTORITO is not writable.\n"
	exit 1
fi

# Check that we've got mkisofs installed 
if [[ ! -f "$MKISOFS" || ! -x "$MKISOFS" ]]; then
    gettext "Cannot find $f\n"
    exit 1
fi


# Determine mkisofs' verbose flag depending on $VERBOSITY.
case $VERBOSITY in
0)	VERBOSE_FLAG=-quiet
	;;
1)	VERBOSE_FLAG=			# mkisofs' default verboseness
	;;
*)	VERBOSE_FLAG=
	i=$VERBOSITY
	while ((i > 0))
	do
		VERBOSE_FLAG="-v $VERBOSE_FLAG"
		(( i -= 1 ))
	done
	;;
esac

# Since mkisofs below will modify the file $ELTORITO in-place, save a copy
# of it first.  Use trap to restore it when this script exits (including
# when user hits control-C).

if [[ "$MACH" = "i386" ]]
then
	BOOTBLOCK=$MEDIA_ROOT/$ELTORITO
	ELTORITO_SAVE=/tmp/${ELTORITO##*/}.$$
	$CP "$MEDIA_ROOT/$ELTORITO" "$ELTORITO_SAVE" || exit 1
	trap '"$CP" "$ELTORITO_SAVE" "$MEDIA_ROOT/$ELTORITO" 2>/dev/null;
		"$RM" -f "$ELTORITO_SAVE"' EXIT
else
	# sun4u/sun4u1/sun4v et al
	BOOTBLOCK=$MEDIA_ROOT/$SPARCBOOT
	SPARCBOOT_SAVE=/tmp/hsfs.bootblock.$$
	$CP "$MEDIA_ROOT/$SPARCBOOT" "$SPARCBOOT_SAVE" || exit 1
	trap '"$CP" "$MEDIA_ROOT/$SPARCBOOT" "$SPARCBOOT_SAVE" 2>/dev/null;
		"$RM" -f $SPARCBOOT_SAVE"' EXIT
fi

# Call mkisofs to do the actual work.
# Note: the "-log-file >(cat -u >&2)" and "2>/dev/null" below is a trick
#	to filter out mkisofs's warning message about being non-conforming
#	to ISO-9660.
# We do some funky architecture-specific stuff here so that we can
# actually create a bootable media image for UltraSPARC systems

sparc_ISOARGS="-G $BOOTBLOCK -B ... -joliet-long -R -U"
i386_ISOARGS="-b boot/grub/stage2_eltorito -boot-info-table "
i386_ISOARGS="$i386_ISOARGS -boot-load-size 4 -c .catalog -d -N "
i386_ISOARGS="$i386_ISOARGS -no-emul-boot -r -relaxed-filenames"
if [[ "$MACH" = "i386" ]]
then
	ISOARGS=$i386_ISOARGS
else
	ISOARGS=$sparc_ISOARGS
fi

$MKISOFS -o "$ISOIMAGE" \
	-allow-leading-dots \
	$ISOARGS \
	-l -ldots \
	-R -J \
	-V "$ISOLABEL" \
	$VERBOSE_FLAG \
	-log-file >($CAT -u >&2) \
	"$MEDIA_ROOT" 2>/dev/null
