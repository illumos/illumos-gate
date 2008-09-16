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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# updatemedia - modify Solaris media with patches and packages
#

readonly PROG=$0
readonly TMP_DIR=${TMPDIR:-/tmp}/${PROG##*/}.$$
readonly LOGFILE=${TMPDIR:-/tmp}/${PROG##*/}-log.$$

# Must-have utilities
readonly CPIO=/bin/cpio
readonly GZIP=/bin/gzip
readonly MKISOFS=/usr/bin/mkisofs
readonly PATCHADD=/usr/sbin/patchadd
readonly LOFIADM=/usr/sbin/lofiadm
readonly MKDIR=/usr/bin/mkdir
readonly RM=/usr/bin/rm
readonly CP=/usr/bin/cp
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
readonly HEAD=/usr/bin/head
readonly SORT=/usr/bin/sort
readonly ROOT_ARCHIVE=/usr/sbin/root_archive


# for gettext
TEXTDOMAIN=SUNW_OST_OSCMD
export TEXTDOMAIN


function usage
{
	gettext "Usage:\n${PROG##*/} -d <media-root> [-v] [-l <label>] [-o <iso>]\n        <pkg_or_patch> [<pkg_or_patch> ...]\n"
	gettext "Options:\n  -d <media-root>\n        Top-level directory of on-disk image of Solaris installation media.\n        This is option must be specified.\n"
	gettext "  -l <label>\n        Label/volume name of the ISO image (if -o option is specified).\n"
	gettext "  -o <iso>\n        Create a Solaris ISO image of <media-root>.\n"
	gettext "  -v\n        Verbose.  Multiple -v options increase verbosity.\n"
}


function check_prereqs
{
	typeset f

	# We must have these utilities.
	for f in $CPIO $GZIP ${ISO:+$MKISOFS} $PATCHADD $ROOT_ARCHIVE
	do 
		if [[ ! -x "$f" ]]
		then
			gettext "Cannot find required utility $f\n"
			exit 1
		fi
	done

	# root_archive unpack_media calls lofiadm -a, which requires
	# write access as determined by /dev/lofictl.  See lofiadm(1m).
	if [[ ! -w /dev/lofictl ]]
	then
		gettext "You do not have enough privileges to run lofiadm -a).\nSee lofiadm(1m) for more information.\n"
		exit 1
	fi
}


function cleanup
{
	$RM -rf "$TMP_DIR"
}


function unpack_media
{
	# Create temp directory to unpack the miniroot.
	$MKDIR -p "$UNPACKED_ROOT"

	# We need to use the unpackmedia option to correctly apply patches
	gettext "Unpacking media ..."
	$ROOT_ARCHIVE unpackmedia "$MEDIA_ROOT" "$UNPACKED_ROOT" > /dev/null 2>&1 
	if [ $? != 0 -a ! -d $MEDIA_ROOT/Solaris_10 ]; then
		# we _do_ care, because we're not patching a Solaris 10
		# update media instance
		gettext "\nThere was an error unpacking the media from $MEDIA_ROOT\n"
		exit 1
	fi
	echo;
}


function repack_media
{
	gettext "Repacking media ..."

	# We need to ensure that we're using the appropriate version
	# of root_archive for the media that we're packing/unpacking.
	# The onnv version of root_archive differs from the S10 version,
	# and this will cause problems on re-packing. So we sneakily
	# use the version that we've just unpacked
	if [ -d $MEDIA_ROOT/Solaris_10 ]; then
		ROOT_ARCHIVE=$MEDIA_ROOT/boot/solaris/bin/root_archive
	fi

	$ROOT_ARCHIVE packmedia "$MEDIA_ROOT" "$UNPACKED_ROOT" > /dev/null 2>&1
	if [ $? != 0 -a ! -d $MEDIA_ROOT/Solaris_10 ]; then
		# we _do_ care, because we're not patching a Solaris 10
		# update media instance
		gettext "\nThere was an error unpacking the media from $MEDIA_ROOT\n"
		exit 1
	fi
	echo;
}


function mkiso
{
	typeset vflag

	# Skip if no ISO image was specified.
	[[ -z "$ISO" ]] && return 0

	gettext "Creating ISO image ..."
	$MKBOOTMEDIA $VERBOSE_OPTS -l "$ISOLABEL" "$MEDIA_ROOT" "$ISO"
	echo;
}


function collect_objs # <pkg_or_patch> ...
{
	typeset obj fail=0

	for obj
	do
		if [[ -f "$obj"/patchinfo ]]
		then
			PATCHES[ ${#PATCHES[*]} ]=$obj
		elif [[ -f "$obj"/pkginfo ]]
		then
			PACKAGES[ ${#PACKAGES[*]} ]=$obj
		else
			gettext "$obj is not in package or patch format\n"
			(( fail += 1 ))
		fi
	done
	(( fail )) && return 1
	return 0
}


function add_pkgs
{
	typeset dudir icmd statusfile

	(( ${#PACKAGES[*]} == 0 )) && return

	statusfile=$TMP_DIR/.add_pkgs.status

	trap '$RM -f $statusfile' EXIT

	dudir=$ITUDIR/$COUNTDIR
	(( COUNTDIR += 1 ))
	$MKDIR "$dudir" || return

	# Add a Driver Update directory on the media
	echo;
	gettext "Adding package(s) to media root."
	$PKG2DU -r "$RELEASE" -f -d "$dudir" $VERBOSE_OPTS \
	    "${PACKAGES[@]}" || return

	# Using the Driver Update above install the packages onto the miniroot.
	echo;
	gettext "Installing package(s) onto miniroot."
	icmd=$dudir/DU/sol_$VERSION/i86pc/Tools/install.sh
	if [[ ! -f "$icmd" ]]
	then
		# This shouldn't happen, but just in case.
		gettext "Cannot find $icmd\n"
		return 1
	fi
	[[ ! -x "$icmd" ]] && $CHMOD a+x "$icmd"

	$RM -f "$statusfile"
        {
		"$icmd" -R "$UNPACKED_ROOT"
		if (( i=$? ))
		then
			echo $i > "$statusfile"
			$TOUCH "$statusfile"  # make sure file is created
		fi
        } 2>&1 | $NAWK -v logfile="$LOGFILE" '
		# Print certain lines from $icmd, save all in logfile.
		/^Installing/ {print}
		/^Installation.*successful/ {print}
		{print >> logfile}
	' || return
	[[ -s "$statusfile" ]] && return $(<$statusfile)
	return 0
}


function add_patches
{
	typeset distdir tmpdir icmd obj patches statusfile

	(( ${#PATCHES[*]} == 0 )) && return

	tmpdir=$TMP_DIR/patches
	statusfile=$TMP_DIR/.add_patches.status

	trap '$RM -rf $tmpdir $statusfile' EXIT

	distdir=$ITUDIR/$COUNTDIR/DU/sol_$VERSION/i86pc
	(( COUNTDIR += 1 ))

	$MKDIR -p "$distdir/Tools" "$distdir/Product" "$tmpdir" || return

	# Patch the miniroot
	echo;
	gettext "Installing patch(es) onto miniroot."
	$RM -f "$statusfile"
	{
		$PATCHADD -udn -C "$UNPACKED_ROOT" "${PATCHES[@]}"
		if (( i=$? ))
		then
			echo $i > "$statusfile"
			$TOUCH "$statusfile" # make sure file is created
		fi
        } 2>&1 | $NAWK -v logfile="$LOGFILE" '
		# Print certain lines from patchadd, save all in logfile.
		/^Patch.*successful/ {print}
		{print >> logfile}
	' || return

	[[ -s "$statusfile" ]] && return $(<$statusfile)

	# Remove patch log files to save space when miniroot is repacked.
	$RM -rf "$UNPACKED_ROOT"/var/sadm/patch

	# Symlink each patch in a temp dir so a single cpio/gzip can work.
	for obj in "${PATCHES[@]}"
	do
		# Get rid of trailing /'s, if any.
		[[ "$obj" == */ ]] && obj=${obj%%+(/)}

		# Make sure it's full pathname.
		[[ "$obj" != /* ]] && obj=$ORIGPWD/$obj

		$LN -s "$obj" "$tmpdir" || return

		# Remember just the file component.
		patches[ ${#patches[*]} ]=${obj##*/}
	done

	# Package up patches as compressed cpio archive.
	echo;
	gettext "Adding patch(es) to media root.\n"
	$RM -f "$statusfile"
	(
		cd "$tmpdir"
		# fd 9 is used later on for filtering out cpio's
		# reporting total blocks to stderr but yet still
		# print other error messages.
		exec 9>&1
		for obj in "${patches[@]}"
		do
			gettext "Transferring patch $obj\n"
			$FIND "$obj/." -follow -print
			if (( i=$? ))
			then
				echo $i > "$statusfile"
				$TOUCH "$statusfile"
				return $i
			fi
		done | $CPIO -oc 2>&1 >&9 | $GREP -v '^[0-9]* blocks' >&2
	) | $GZIP -9 > "$distdir/Product/patches.gz" || return

	[[ -s "$statusfile" ]] && return $(<$statusfile)

	# Create install.sh
	$CAT > "$distdir/Tools/install.sh" <<"EOF"
#!/sbin/sh
# install.sh -R <basedir> - install patches to basedir
basedir=/
toolsdir=`dirname $0`
tmpdir=/tmp/`basename $0`.$$
trap "/bin/rm -rf $tmpdir" 0
while getopts "R:" arg
do
        case "$arg" in
                R) basedir=$OPTARG;;
        esac
done
/bin/mkdir -p "$tmpdir" || exit
tmpfile=$tmpdir/patches
patchdir=$tmpdir/patchdir
/bin/mkdir "$patchdir" || exit
/usr/bin/gzip -c -d "$toolsdir/../Product/patches.gz" > $tmpfile || exit
cd "$patchdir"
/bin/cpio -idum < "$tmpfile" || exit
/usr/sbin/patchadd -R "$basedir" -nu *
EOF
	$CHMOD a+rx "$distdir/Tools/install.sh"

}


#
# Main
#
trap cleanup EXIT

ISO=
ISOLABEL=
MEDIA_ROOT=
VERBOSE_LEVEL=0
VERBOSE_OPTS=

while getopts ':d:o:l:v' opt
do
	case $opt in
	d)	MEDIA_ROOT=$OPTARG
		;;
	o)	ISO=$OPTARG
		if [ ! -z `echo $ISO | $GREP "^/tmp"` ]; then
		        gettext "ISO images will not be created on /tmp.\nPlease choose a different output location.\n"
			exit 3
		fi
		;;
	l)	ISOLABEL=$OPTARG
		;;
	v)	(( VERBOSE_LEVEL += 1 ))
		VERBOSE_OPTS="${VERBOSE_OPTS:--}$opt"	# collect -v options
		;;
	:)	gettext "Option -$OPTARG missing argument.\n"
		usage
		exit 1
		;;
	*)	gettext "Option -$OPTARG is invalid.\n"
		usage
		exit 2
		;;
	esac
done
shift 'OPTIND - 1'

unset PACKAGES PATCHES				# reset arrays
collect_objs "$@"

# If there are no packages or patches, then print info and we're done.
if (( ${#PACKAGES[*]} == 0 && ${#PATCHES[*]} == 0 ))
then
	gettext "No valid package or patch was specified.\nPackages and patches must be unpacked.\n"
	usage
	exit 1
fi

# -d option must be specified
if [[ -z "$MEDIA_ROOT" ]]
then
	gettext "No media root (-d option) was specified.\n"
	usage
	exit 1
fi

check_prereqs		# must be called after $ISO is possibly set

# Verify it's a Solaris install media.
SOLARIS_DIR=$($LS -d $MEDIA_ROOT/Solaris* 2>/dev/null)
if [[ -z "$SOLARIS_DIR" || ! -d "$SOLARIS_DIR/Tools/Boot" ]]
then
	gettext "$MEDIA_ROOT is not valid Solaris install media.\n"
	exit 1
fi

$MKDIR -p "$TMP_DIR" || exit 1

# Extract the Solaris release number from the Solaris_* directory and the
# corresponding version number.  As defined by the ITU spec, a Solaris release
# number 5.x corresponds to version number 2x (e.g. 5.10 -> 210).
RELEASE=5.${SOLARIS_DIR##*Solaris_}
VERSION=$(echo $RELEASE | $SED 's/5\./2/')

# If user didn't specify ISO label, use the Solaris_* dir as label.
${ISOLABEL:=${SOLARIS_DIR##*/}}

# Verify miniroot
MINIROOT=$MEDIA_ROOT/boot/x86.miniroot
if [[ ! -f "$MINIROOT" ]]
then
	gettext "No boot/x86.miniroot under media root.\n"
	exit 1
fi

# Where to unpack the miniroot.
UNPACKED_ROOT=${TMP_DIR}/miniroot

# Create the ITU directory on the media, if necessary
ITUDIR=$MEDIA_ROOT/ITUs
$MKDIR -p "$ITUDIR" || exit 1

# The ITU directory might contain multiple driver updates already, each in a
# separate numbered subdirectory.  So look for the subdirectory with the
# highest number and we'll add the packages and patches on the next one.
typeset -Z3 COUNTDIR
COUNTDIR=$($LS -d "$ITUDIR"/+([0-9]) 2>/dev/null | $SED 's;.*/;;' |
		$SORT -rn | $HEAD -1)
if [[ $COUNTDIR == *( ) ]]
then
	COUNTDIR=0
else
	(( COUNTDIR += 1 ))
fi

unpack_media || exit
add_pkgs && add_patches
if (( status=$? )) && [[ -s "$LOGFILE" ]]
then
	echo;
	gettext "A package or patch installation has failed.\nMessages from pkgadd and patchadd have been saved in $LOGFILE\n"
	exit $status
else
	$RM -f "$LOGFILE"
fi
print
repack_media || exit
mkiso
