#!/bin/ksh93 -p
#
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# pkg2du - convert driver packages to Driver Update (DU) format
#

readonly PROG=$0
readonly ORIGPWD=$PWD
readonly TMP_DIR=${TMPDIR:-/tmp}/${PROG##*/}.$$

# Must-have utilities
readonly CPIO=/usr/bin/cpio
readonly GZIP=/usr/bin/gzip
readonly MKISOFS=/usr/bin/mkisofs
readonly PATCHADD=/usr/sbin/patchadd
readonly PKGTRANS=/usr/bin/pkgtrans
readonly ROOT_ARCHIVE=/usr/sbin/root_archive
readonly LOFIADM=/usr/sbin/lofiadm
readonly MKDIR=/usr/bin/mkdir
readonly RM=/usr/bin/rm
readonly CP=/usr/bin/cp
readonly HEAD=/usr/bin/head
readonly SORT=/usr/bin/sort
readonly MKBOOTMEDIA=/usr/bin/mkbootmedia
readonly PKG2DU=/usr/bin/pkg2du
readonly TOUCH=/usr/bin/touch
readonly NAWK=/usr/bin/nawk
readonly CHMOD=/usr/bin/chmod
readonly GREP=/usr/bin/grep
readonly LS=/usr/bin/ls
readonly LN=/usr/bin/ln
readonly SED=/usr/bin/sed
readonly CAT=/usr/bin/cat
readonly FIND=/usr/bin/find

# for gettext
TEXTDOMAIN=SUNW_OST_OSCMD
export TEXTDOMAIN


function usage
{
	gettext "Usage:\n${PROG##*/} -r <release> [-f] [-v] [-d <dir>] [-o <iso>] [-l <label>]\n        <pkg> [<pkg> ...]\n"
	gettext "Options:\n  -d <dir>\n        Directory where the Driver Update directory should be created.\n"
	gettext "  -o <iso>\n        Create a Solaris ISO image of the Driver Update directory.\n"
	gettext "  -f\n        If <dir>/DU or <iso> exists, remove it without asking first.\n"
	gettext "  -l <label>\n        Label/volume name of the ISO image (if -o option is specified).\n"
	gettext "  -r <release>\n        Solaris release number to use.  It takes the form of 5.10.\n        This option must be specified.\n"
	gettext "  -v\n        Verbose.  Multiple -v options increase verbosity.\n"
	echo;
}


function check_prereqs
{
	typeset f

	# We must have these utilities.
	for f in $GZIP ${ISO:+$MKISOFS} $PKGTRANS
	do 
		if [[ ! -x "$f" ]]
		then
			gettext "Cannot find required utilty $f"
			exit 1
		fi
	done
}


function cleanup
{
	$RM -rf "$TMP_DIR"
}


function is_overwrite
{
	typeset arg=$1
	typeset -l ans

	[[ $FORCE == yes ]] && return 0

	while true
	do
		gettext "$arg already exists. Overwrite it? (y/n) "
		read ans
		case $ans in
		y*|Y*) return 0 ;;		# go ahead overwrite
		n*|N*) return 1 ;;		# don't overwrite
		esac
	done
	echo;
}


function collect_objs # <pkg> ...
{
	typeset obj fail=0

	for obj
	do
		if [[ -f "$obj"/pkginfo ]]
		then
			PACKAGES[ ${#PACKAGES[*]} ]=$obj
		else
			gettext "$obj is not in package format\n"
			(( fail += 1 ))
		fi
	done
	(( fail )) && return 1
	return 0
}


function mkdu
{
	typeset distdir tmpdudir pkgs obj statusfile

	trap '/bin/rm -rf $statusfile $tmpdudir' EXIT

	# Create DU directory first.
	distdir=$ROOTDIR/DU/sol_$VERSION/i86pc
	$MKDIR -p "$distdir/Tools" "$distdir/Product"

	# Unfortunately pkgtrans insists that all packages must be in
	# <device1> (see pkgtrans(1)).  The packages can't have any path
	# components.  So we'll create a temporary directory first and then
	# symlinks to the specified packages.  Then run pkgtrans with
	# the temporary directory as <device1>.
	tmpdudir=$TMP_DIR/mkdu
	$MKDIR -p "$tmpdudir"

	for obj in "${PACKAGES[@]}"
	do
		# Get rid of trailing /'s, if any.
		[[ "$obj" == */ ]] && obj=${obj%%+(/)}

		# Make sure it's a full pathname.
		[[ "$obj" != /* ]] && obj=$ORIGPWD/$obj

		$LN -s "$obj" "$tmpdudir" || exit 1

		# Remember just the file component.
		pkgs[ ${#pkgs[*]} ]=${obj##*/}
	done

	# Package up packages as compressed data stream.
	statusfile=$TMP_DIR/.pkgtrans.status
	{
		$PKGTRANS -s "$tmpdudir" /dev/stdout "${pkgs[@]}"
		echo $? > $statusfile
		$TOUCH $statusfile	# make sure file is created
	} | $GZIP -9 > "$distdir/Product/pkgs.gz"

	[[ -s $statusfile && $(<$statusfile) != 0 ]] && return 1

	# Create admin file for pkgadd
	$CAT > "$distdir/Tools/admin" <<"EOF"
mail=
instance=unique
partial=nocheck
runlevel=nocheck
idepend=nocheck
rdepend=nocheck
space=nocheck
setuid=nocheck
conflict=nocheck
action=nocheck
EOF

	# Create install.sh
	$CAT > "$distdir/Tools/install.sh" <<"EOF"
#!/sbin/sh
# install.sh -R <basedir> - install packages to basedir
basedir=/
toolsdir=`dirname $0`
tmpfile=/tmp/`basename $0`.$$
while getopts "R:" arg
do
        case "$arg" in
                R) basedir=$OPTARG;;
        esac
done
/usr/bin/gzip -c -d "$toolsdir/../Product/pkgs.gz" > $tmpfile &&
	/usr/sbin/pkgadd -R "$basedir" -d "$tmpfile" -a "$toolsdir/admin" all
status=$?
/bin/rm -f "$tmpfile"
exit $status
EOF
	$CHMOD a+rx "$distdir/Tools/install.sh"
}


function mkiso
{
	typeset vflag

	# Skip if no ISO image was specified.
	[[ -z "$ISO" ]] && return 0

	# Determine mkisofs' verbose flag depending on $VERBOSE_LEVEL.
	case $VERBOSE_LEVEL in
	0)	vflag=-quiet
		;;
	1)	vflag=				# mkisofs' default verboseness
		;;
	*)	vflag=
		i=$VERBOSE_LEVEL
		while ((i > 0))
		do
			vflag="-v $vflag"
			(( i -= 1 ))
		done
		;;
	esac

	(( VERBOSE_LEVEL )) && gettext "Creating ISO image ..."

	# Note: the "-log-file >(cat -u >&2)" and "2>/dev/null" below is a
	#	trick to filter out mkisofs's warning message about being
	#	non-conforming to ISO-9660.
	$MKISOFS -o "$ISO" \
		-relaxed-filenames \
		-allow-leading-dots \
		-N -l -d -D -r \
		-R -J \
		-V "$LABEL" \
		$vflag \
		-log-file >(/bin/cat -u >&2) \
		"$ROOTDIR" 2>/dev/null
}


#
# Main
#
trap cleanup EXIT

FORCE=
ISO=
LABEL=
RELEASE=
ROOTDIR=
VERBOSE_LEVEL=0

while getopts ':d:fo:l:r:v' opt
do
	case $opt in
	d)	ROOTDIR=$OPTARG
		;;
	f)	FORCE=yes
		;;
	o)	ISO=$OPTARG
		if [ ! -z `echo $ISO | $GREP "^/tmp"` ]; then
		        gettext "ISO images will not be created on /tmp.\n"
			gettext "Please choose a different output location.\n"
			exit 3
		fi
		;;
	l)	LABEL=$OPTARG
		;;
	r)	RELEASE=$OPTARG
		;;
	v)	(( VERBOSE_LEVEL += 1 ))
		;;
	:)	gettext "Option -$OPTARG missing argument."
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

# Release number must be specified.
if [[ -z "$RELEASE" ]]
then
	gettext "Solaris release number must be specified (-r option).\n"
	usage
	exit 1
fi

# Verify release number.  Allow major.minor or major.minor.micro format.
if [[ $RELEASE != +([0-9]).+([0-9])?(.+([0-9])) ]]
then
	gettext "Invalid release number: $RELEASE\n"
	exit 1
fi
VERSION=$(echo $RELEASE | $SED 's/5\./2/')

# Either or both of -d or -o option must be specified.
if [[ -z "$ROOTDIR" && -z "$ISO" ]]
then
	gettext "Either -d or -o option (or both) must be specified.\n"
	usage
	exit 1
fi

# There must be at least one package.
if (( $# == 0 ))
then
	gettext "No package was specified.\n"
	usage
	exit 1
fi

# Check and collect packages
unset PACKAGES
collect_objs "$@" || exit 1

# Default label for ISO image
LABEL=${LABEL:-DU sol_$VERSION}

check_prereqs		# must be called after $ISO is possibly set

# If an ISO image was specified, check its parent directory and get its
# full pathname.
unset ISODIR
if [[ -n "$ISO" ]]
then
	if [[ "$ISO" = */* ]]
	then
		ISODIR=$(cd "${ISO%/*}" 2>/dev/null && pwd -P)
		if (( $? ))
		then
			gettext "Can't access parent directory of ISO image\n"
			exit 1
		fi
	else
		ISODIR=$(pwd -P)
	fi
fi

# If user specified a media root directory, verify it exists, else use
# a temporary directory.
if [[ -n "$ROOTDIR" ]]
then
	$MKDIR -p "$ROOTDIR";
	if [ $? != 0 ]; then
		gettext "$ROOTDIR is not a directory.\n"
		exit 1
	elif [[ ! -w "$ROOTDIR" ]] then
		gettext "Directory $ROOTDIR is not writable.\n"
		exit 1
	fi
	# If an ISO image path is also specified, make sure it's not under
	# $ROOTDIR since we're going to take the ISO image of $ROOTDIR.
	if [[ -n "$ISODIR" ]]
	then
		realroot=$(cd "$ROOTDIR" 2>/dev/null && pwd -P)
		if [[ "$ISODIR" = "$realroot"?(/*) ]]
		then
			gettext "ISO image must not be under Driver Update's parent directory ($realroot)\n"
			exit 1
		fi
	fi
else
	ROOTDIR=$TMP_DIR/root
fi

# If DU directory already exists, ask user permission to remove it unless -f
# option was specified.
if [[ -d "$ROOTDIR/DU" ]]
then
	is_overwrite "$ROOTDIR/DU" || exit 0
	$RM -rf "$ROOTDIR/DU"
fi

# If ISO image already exists, ask user permission to remove it unless -f
# option was specified.
if [[ -f "$ISO" ]]
then
	is_overwrite "$ISO" || exit 0
	$RM -f "$ISO"
fi

# Create DU directory and the ISO image (if requested).
mkdu && mkiso
if (( $? ))
then
	$RM -rf "$ROOTDIR/DU"
	[[ -n "$ISO" ]] && $RM -f "$ISO"
	exit 1
fi
exit 0
