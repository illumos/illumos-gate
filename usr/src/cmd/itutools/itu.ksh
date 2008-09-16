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
# itu - converts packages to Driver Update format and patches Solaris install
#	media for Install Time Update (ITU).
#

readonly PROG=$0
readonly ORIGPWD=$PWD

# Must-have utilities
readonly CPIO=/usr/bin/cpio
readonly GZIP=/usr/bin/gzip
readonly MKISOFS=/usr/bin/mkisofs
readonly PATCHADD=/usr/sbin/patchadd
readonly PKGTRANS=/usr/bin/pkgtrans
readonly PKGADD=/usr/sbin/pkgadd
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

# Relative to a Solaris media root.
readonly ELTORITO=boot/grub/stage2_eltorito

readonly TMP_DIR=${TMPDIR:-/tmp}/${PROG##*/}.$$
readonly LOGFILE=${TMPDIR:-/tmp}/${PROG##*/}-log.$$

# Paths we need.
export PATH=/usr/bin:/usr/sbin:/sbin:/boot/solaris/bin:$PATH

# for gettext
TEXTDOMAIN=SUNW_OST_OSCMD
export TEXTDOMAIN


function cleanup
{
	$RM -rf "$TMP_DIR"
}


function usage_long
{
	usage_short
	print -u2
	usage_options
}


function usage_short
{
	gettext "Usage:\n"
	gettext "${PROG##*/} makedu -r solaris_release [-v] [-f] [-d output_dir]\n        [-o iso_file] [-l iso_label] package [package ...]\n"
	gettext "${PROG##*/} patchmedia -R media_root [-v] [-f]\n        [-o iso_file] [-l iso_label] pkg_or_patch [pkg_or_patch ...]\n"
	gettext "${PROG##*/} makeiso -o iso_file [-v] [-f] [-l iso_label] media_root\n"
}


function usage_options {
	gettext "Options:\n"
	gettext "  -d output_dir\n        Directory where the Driver Update directory should be created.\n"
	gettext "  -f\n        If output_dir/DU or iso_file already exists, remove it without\n        asking first.\n"
	gettext "  -l iso_label\n        Label/volume name of the ISO image (if -o option is specified).\n"
	gettext "  -o iso_file\n        Path of ISO image file to create. For
	subcommands patchmedia and\n        makeiso this will be a bootable ISO image.\n        This option must be specified for subcommand makeiso.\n"
	gettext "  -R media_root\n        Top-level directory of on-disk image of Solaris installation media.\n        This option must be specified for subcommand patchmedia.\n"
	gettext "  -r solaris_release\n        Solaris release number for which the Driver Update is intended.\n        It takes the form of 5.10.\n        This option must be specified for subcommand makedu.\n"
	gettext "  -v\n        Verbose. Multiple -v options increase verbosity.\n"

	echo;
}


#
# Process command line options.
# Note: since $OPTIND is a local variable inside functions, upon return
#	from this function global variable $MYOPTIND is set to this value.
#
function process_options # <arg> ...
{
	typeset opt optlist

	case "$SUBCOMMAND" in
	makedu)		optlist='d:fl:o:r:v' ;;
	patchmedia)	optlist='fl:o:R:v' ;;
	makeiso)	optlist='fl:o:v' ;;
	esac

	while getopts ":$optlist" opt
	do
		case $opt in
		d)	DU_OUTDIR=$OPTARG
			;;
		f)	FORCE=1
			;;
		l)	ISOLABEL=$OPTARG
			;;
		o)	ISO=$OPTARG
			if [ ! -z `echo $ISO | $GREP "^/tmp"` ]; then
				gettext "ISO images will not be created on /tmp.\n"
				gettext "Please choose a different output location.\n"
			    exit 3
			fi
			;;
		R)	MEDIA_ROOT=$OPTARG
			;;
		r)	RELEASE=$OPTARG
			;;
		v)	(( VERBOSE_LEVEL += 1 ))
			VERBOSE_OPTS="${VERBOSE_OPTS:--}$opt" # collect options
			;;
		:)	gettext "Option -$OPTARG missing argument.\n"
			usage_short
			return 1
			;;
		*)	gettext "Option -$OPTARG invalid for $SUBCOMMAND.\n"
			usage_short
			return 1
			;;
		esac
	done

	MYOPTIND=$OPTIND
	return 0
}


#
# Check some prerequisites
#
function check_prereqs
{
	typeset utils f

	# List of must-have utilities depends on subcommand.
	case "$SUBCOMMAND" in
	makedu)
		set -A utils $GZIP ${ISO:+$MKISOFS} $PKGTRANS
		;;
	patchmedia)
		set -A utils $CPIO $GZIP ${ISO:+$MKISOFS} $PATCHADD \
			$ROOT_ARCHIVE
		;;
	makeiso)
		set -A utils $MKISOFS
		;;
	esac

	for f in "${utils[@]}"
	do
		if [[ ! -x "$f" ]]
		then
			gettext "Can't find required utility $f.\n"
			return 1
		fi
	done

	# Subcommand packmedia uses the "root_archive unpack_media" command
	# which calls lofiadm -a, which requires write access as
	# determined by /dev/lofictl.  See lofiadm(1m).
	if [[ $SUBCOMMAND = patchmedia && ! -w /dev/lofictl ]]
	then
		gettext "You don't have enough privileges to run lofiadm -a.\n"
		gettext "See lofiadm(1m) for more information.\n"
		return 1
	fi

	return 0
}


#
# Verifies the given packages and collects them in the PACKAGES array.
#
function collect_packages # <arg> ...
{
	typeset obj

	for obj in "$@"
	do
		if [[ ! -e "$obj" ]]
		then
			gettext "Can't find package $obj.\n"
			return 1
		elif [[ ! -f "$obj/pkginfo" ]]
		then
			gettext "$obj is not a package.\n"
			return 1
		fi
		PACKAGES[ ${#PACKAGES[*]} ]=$obj
	done
	return 0
}


#
# Verifies the given packages and patches.  Packages are then collected in
# the array PACKAGES.  Patches are stored in the PATCHES array.
#
function collect_packages_patches # <arg> ...
{
	typeset obj

	for obj in "$@"
	do
		if [[ -f "$obj/patchinfo" ]]
		then
			# Collect patches.
			PATCHES[ ${#PATCHES[*]} ]=$obj
		elif [[ -f "$obj/pkginfo" ]]
		then
			# Collect packages.
			PACKAGES[ ${#PACKAGES[*]} ]=$obj
		elif [[ -e "$obj" ]]
		then
			gettext "$obj is not a package or patch.\n"
			return 1
		else
			gettext "$obj does not exist.\n"
			return 1
		fi
	done
	return 0
}


#
# Ask user whether to overwrite an object, unless -f option was given.
#
function is_overwrite
{
	typeset arg=$1
	typeset -l ans

	(( FORCE )) && return 0
	while true
	do
		gettext "$arg already exists. Overwrite it? (y/n) "
		read ans
		case $ans in
		y*|Y*) return 0 ;;		# go ahead, overwrite
		n*|N*) return 1 ;;		# don't overwrite
		esac
	done
}


#
# Check the format of the Solaris release number $RELEASE.
# Also set $VERSION (for DU format) based on $RELEASE.
#
function check_release
{
	# Allow Major.Minor or Major.Minor.Micro format.
	if [[ $RELEASE != +([0-9]).+([0-9])?(.+([0-9])) ]]
	then
		gettext "Invalid release number specified: $RELEASE.\n"
		return 1
	fi

	# As defined by the ITU spec, a Solaris release number 5.x corresponds
	# to version number 2x (e.g. 5.10 -> 210). Hopefully, by the time we
	# do a 6.x Release we won't need ITUs any more.
	VERSION=$(echo $RELEASE | $SED 's/5\./2/')
}


#
# If an ISO file was specified, get realpath of its parent directory ($ISODIR).
# If the ISO file already exists, ask user to overwrite it, unless -f option
# was specified.
#
function check_iso
{
	if [[ "$ISO" = */* ]]
	then
		ISODIR=$(cd "${ISO%/*}" 2>/dev/null && pwd -P)
		if (( $? ))
		then
			gettext "Can't access parent directory of ISO image.\n"
			return 1
		fi
	else
		ISODIR=$(pwd -P)
	fi

	if [[ -f "$ISO" ]]
	then
		is_overwrite "$ISO" || return 2
		$RM -f "$ISO"
	fi

	return 0
}


#
# If specified, check the Driver Update output directory $DU_OUTDIR (-d option).
# Else set $DU_OUTDIR to a temporary directory.  Also if $DU_OUTDIR/DU
# already exists, ask user whether to overwrite it, unless -f option was given.
#
function check_dudir
{
	typeset	realpath

	if [[ -z "$DU_OUTDIR" ]]
	then
		DU_OUTDIR=$TMP_DIR/dudir
		return 0
	fi

	# Verify user-specified DU output directory.
	if [[ ! -d "$DU_OUTDIR" ]]
	then
		if [ `$MKDIR -p $DU_OUTDIR` ]; then
			gettext "$DU_OUTDIR is not a directory.\n"
			return 1
		fi
	elif [[ ! -w "$DU_OUTDIR" ]]
	then
		gettext "Directory $DU_OUTDIR is not writable.\n"
		return 1
	fi

	# If an ISO image path is also specified, make sure it's not under
	# $DU_OUTDIR since we might take the ISO image of $DU_OUTDIR.
	if [[ -n "$ISODIR" ]]
	then
		realpath=$(cd "$DU_OUTDIR" 2>/dev/null && pwd -P)
		if [[ "$ISODIR" = "$realpath"?(/*) ]]
		then
			gettext "ISO image must not be under Driver Update's output directory ($realpath).\n"
			return 1
		fi
	fi

	# If the DU directory already exists, ask user permission to
	# remove it unless -f option was given.
	if [[ -d "$DU_OUTDIR/DU" ]]
	then
		is_overwrite "$DU_OUTDIR/DU" || return 2
		$RM -rf "$DU_OUTDIR/DU" || return 1
	fi

	return 0
}


#
# Verify $MEDIA_ROOT is indeed a Solaris install media.
#
function check_media_root
{
	if [[ ! -d $(echo "$MEDIA_ROOT"/Solaris*/Tools/Boot) ]]
	then
		gettext "$MEDIA_ROOT is not a Solaris install media.\n"
		return 1
	fi
	return 0
}


#
# Verify there's a miniroot file under $MEDIA_ROOT.  Also set $MINIROOT
# to the path of the miniroot.
#
function check_miniroot
{
	MINIROOT=$MEDIA_ROOT/boot/x86.miniroot
	if [[ ! -f "$MINIROOT" ]]
	then
		gettext "Can't find $MINIROOT.\n"
		return 1
	fi
	return 0
}


#
# Create a non-bootable ISO image of the given directory.
#
function create_nonboot_iso # <dir>
{
	typeset dir vflag i

	if (( $# != 1 ))
	then
		gettext "create_nonboot_iso missing argument.\n"
		return 1
	fi
	dir=$1

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

	print "Creating ISO image ..."

	# Note: the "-log-file >(cat -u >&2)" and "2>/dev/null" below is a
	#	trick to filter out mkisofs's warning message about being
	#	non-conforming to ISO-9660.
	$MKISOFS -o "$ISO" \
		-relaxed-filenames \
		-allow-leading-dots \
		-N -l -d -D -r \
		-R -J \
		-V "$ISOLABEL" \
		$vflag \
		-log-file >(cat -u >&2) \
		"$dir" 2>/dev/null
}


#
# Create a bootable Solaris ISO image of the given Solaris install directory.
#
function create_bootable_iso # <dir>
{
	typeset dir vflag saved i

	if (( $# != 1 ))
	then
		gettext "create_bootable_iso missing argument.\n"
		return 1
	fi
	dir=$1

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

	# Verify the El Torito file exists under media root.  And if so,
	# verify it's writable since it will be modified with some boot
	# information by mkisofs' -boot-info-table option.
	if [[ ! -f "$dir/$ELTORITO" ]]
	then
		gettext "Can't find $dir/$ELTORITO.\n"
		return 1
	elif [[ ! -w "$dir/$ELTORITO" ]]
	then
		gettext "$dir/$ELTORITO is not writable.\n"
		return 1
	fi

	gettext "Creating bootable ISO image ..."

	# Since mkisofs below will modify the file $ELTORITO in-place, save
	# a copy of it first.
	saved=$TMP_DIR/${ELTORITO##*/}
	$CP -f "$dir/$ELTORITO" "$saved" || return

	# Note: the "-log-file >(cat -u >&2)" and "2>/dev/null" below is a
	#	trick to filter out mkisofs's warning message about being
	#	non-conforming to ISO-9660.
	$MKISOFS -o "$ISO" \
		-b "$ELTORITO" \
		-c .catalog \
		-no-emul-boot \
		-boot-load-size 4 \
		-boot-info-table \
		-relaxed-filenames \
		-allow-leading-dots \
		-N -l -d -D -r \
		-R -J \
		-V "$ISOLABEL" \
		$vflag \
		-log-file >(cat -u >&2) \
		"$dir" 2>/dev/null
	i=$?

	# Restore saved El Torito file
	$CP -f "$saved" "$dir/$ELTORITO" 2>/dev/null

	return $i
}


#
# Create a Driver Update (DU) format directory from packages
#
function create_du
{
	typeset distdir tmpdudir pkgs obj statusfile

	# Create DU directory first.
	distdir=$DU_OUTDIR/DU/sol_$VERSION/i86pc
	$MKDIR -p "$distdir/Tools" "$distdir/Product"

	# Unfortunately pkgtrans insists that all packages must be in
	# <device1> (see pkgtrans(1)).  The packages can't have any path
	# components.  So we'll create a temporary directory first and then
	# symlinks to the specified packages.  Then run pkgtrans with
	# the temporary directory as <device1>.
	tmpdudir=$TMP_DIR/create_du
	$RM -rf "$tmpdudir"
	$MKDIR -p "$tmpdudir"

	for obj in "${PACKAGES[@]}"
	do
		# Get rid of trailing /'s, if any.
		[[ "$obj" == */ ]] && obj=${obj%%+(/)}

		# Make sure it's full pathname.
		[[ "$obj" != /* ]] && obj=$ORIGPWD/$obj

		ln -s "$obj" "$tmpdudir" || return

		# Remember just the file component.
		pkgs[ ${#pkgs[*]} ]=${obj##*/}
	done

	# Package up packages as compressed data stream.
	statusfile=$TMP_DIR/.pkgtrans.status
	(
		# Use fd 9 for redirecting pkgtrans' "Transferring..."
		# messages which normally go to stderr to current stdout
		# (not the following pipeline's stdout).
		exec 9>&1
		{
			$PKGTRANS -s "$tmpdudir" /dev/stdout "${pkgs[@]}" 2>&9
			echo $? > $statusfile
			$TOUCH $statusfile	# make sure file is created
		} | $GZIP -9 > "$distdir/Product/pkgs.gz"
	)

	[[ -s $statusfile && $(<$statusfile) != 0 ]] && return 1

	# Create admin file for pkgadd
	$CAT > "$distdir/Tools/admin" <<"EOF"
mail=
instance=overwrite
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
rm -f "$tmpfile"
exit $status
EOF
	$CHMOD a+rx "$distdir/Tools/install.sh"
}


#
# Unpack the miniroot of a Solaris install media.
#
function unpack_media
{
	# Create temp directory to unpack the miniroot.
	$MKDIR -p "$UNPACKED_ROOT"

	# We need to use the unpackmedia option to correctly apply patches
	gettext "Unpacking media ... "
	$ROOT_ARCHIVE unpackmedia "$MEDIA_ROOT" "$UNPACKED_ROOT" > /dev/null 2>&1 
	if [ $? != 0 -a ! -d $MEDIA_ROOT/Solaris_10 ]; then
		# we _do_ care, because we're not patching a Solaris 10
		# update media instance
		gettext "There was an error unpacking the media from $MEDIA_ROOT\n"
		exit 1
	fi
}


#
# Pack an unpacked miniroot onto a Solaris install media.
#
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
		gettext "There was an error unpacking the media from $MEDIA_ROOT\n"
		exit 1
	fi
}


#
# Add packages to a Solaris install media.  Also install these packages
# onto the miniroot.
#
function add_pkgs
{
	typeset icmd statusfile i

	(( ${#PACKAGES[*]} == 0 )) && return

	statusfile=$TMP_DIR/.add_pkgs.status

	DU_OUTDIR=$ITUDIR/$ITU_COUNTDIR
	(( ITU_COUNTDIR += 1 ))
	$MKDIR "$DU_OUTDIR" || return

	#
	# Add a Driver Update directory on the media
	#
	echo;
	gettext "Adding package(s) to media root.\n"
	create_du || return

	#
	# Using the Driver Update above install the packages onto the miniroot.
	#
	echo;
	gettext "Installing package(s) onto miniroot.\n"
	icmd=$DU_OUTDIR/DU/sol_$VERSION/i86pc/Tools/install.sh
	if [[ ! -f "$icmd" ]]
	then
		# This shouldn't happen, but just in case.
		gettext "Cannot find $icmd.\n"
		return 1
	fi
	[[ ! -x "$icmd" ]] && chmod a+x "$icmd"

	$RM -f "$statusfile"
        {
		"$icmd" -R "$UNPACKED_ROOT"
		if (( i=$? ))
		then
			echo $i > "$statusfile"
			$TOUCH "$statusfile"  # make sure file is created
		fi
        } 2>&1 | $NAWK -v logfile="$LOGFILE" -v vlevel=$VERBOSE_LEVEL '
		# If not verbose, print certain lines from patchadd.
		(vlevel == 0) && /^Installing/ {print}
		(vlevel == 0) && /^Installation.*successful/ {print}

		# If verbose, print every line to stderr.
		(vlevel > 0) {print > "/dev/stderr"}

		# Save every line to logfile.
		{print >> logfile}
	' || return
	[[ -s "$statusfile" ]] && return $(<$statusfile)
	return 0
}


#
# Add patches to a Solaris install media.  Also patch the miniroot with
# these patches
#
function add_patches
{
	typeset distdir tmpdir icmd obj patches statusfile

	(( ${#PATCHES[*]} == 0 )) && return

	tmpdir=$TMP_DIR/patches
	statusfile=$TMP_DIR/.add_patches.status

	$RM -rf "$tmpdir"

	distdir=$ITUDIR/$ITU_COUNTDIR/DU/sol_$VERSION/i86pc
	(( ITU_COUNTDIR += 1 ))

	$MKDIR -p "$distdir/Tools" "$distdir/Product" "$tmpdir" || return

	#
	# Add packages onto media root
	#
	echo;
	gettext "Adding patch(es) to media root.\n"

	# Symlink each patch in a temp dir so a single cpio/gzip can work.
	for obj in "${PATCHES[@]}"
	do
		# Get rid of trailing /'s, if any.
		[[ "$obj" == */ ]] && obj=${obj%%+(/)}

		# Make sure it's a full pathname.
		[[ "$obj" != /* ]] && obj=$ORIGPWD/$obj

		$LN -s "$obj" "$tmpdir" || return

		# Remember just the file component.
		patches[ ${#patches[*]} ]=${obj##*/}
	done

	# Package up patches as compressed cpio archive.
	$RM -f "$statusfile"
	(
		# Save current stdout as fd 8.  This doesn't point to the
		# gzip pipeline below.
		exec 8>&1

		{
			# Fd 9 is used later on for filtering out cpio's
			# reporting total blocks to stderr but yet still
			# print other error messages.  fd 9 refers to the
			# pipeline to gzip.
			exec 9>&1

			cd "$tmpdir"
			for obj in "${patches[@]}"
			do
				print -u8 "Transferring patch $obj."
				$FIND "$obj/." -follow -print
				if (( i=$? ))
				then
					echo $i > "$statusfile"
					$TOUCH "$statusfile"
					return $i
				fi
			done | $CPIO -oc 2>&1 >&9 | $GREP -v '^[0-9]* blocks' >&2
		} | $GZIP -9 > "$distdir/Product/patches.gz"
	) || return

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
patchadd -R "$basedir" -nu *
EOF
	$CHMOD a+rx "$distdir/Tools/install.sh"

	#
	# Patch the miniroot
	#
	echo;
	gettext "Installing patch(es) onto miniroot.\n"
	$RM -f "$statusfile"
	{
		$PATCHADD -udn -C "$UNPACKED_ROOT" "${PATCHES[@]}"
		if (( i=$? ))
		then
			echo $i > "$statusfile"
			$TOUCH "$statusfile" # make sure file is created
		fi
        } 2>&1 | $NAWK -v logfile="$LOGFILE" -v vlevel=$VERBOSE_LEVEL '
		# If not verbose, print certain lines from patchadd.
		(vlevel == 0) && /^Patch.*successful/ {print}

		# If verbose, print every line to stderr.
		(vlevel > 0) {print > "/dev/stderr"}

		# Save every line to logfile.
		{print >> logfile}
	' || return

	[[ -s "$statusfile" ]] && return $(<$statusfile)

	# Remove patch log files to save space when miniroot is repacked.
	$RM -rf "$UNPACKED_ROOT"/var/sadm/patch
}


#
# Starting point for makedu subcommand:
#
#	Convert packages into Driver Update (DU) directory format.
#
function makedu # <arg> ...
{
	typeset i

	process_options "$@" || return
	shift 'MYOPTIND - 1'

	if (( $# == 0 ))
	then
		gettext "Please specify one or more packages.\n"
		usage_short
		return 1
	fi

	# Release number must be specified.
	if [[ -z "$RELEASE" ]]
	then
		gettext "Please specify Solaris release number (-r option).\n"
		usage_short
		return 1
	fi
	check_release || return

	# Either -d or -o option, or both, must be specified.
	if [[ -z "$DU_OUTDIR" && -z "$ISO" ]]
	then
		gettext "Please specify either -d or -o option (or both).\n"
		usage_short
		return 1
	fi

	if [[ -n "$ISO" ]]
	then
		check_iso || return
		${ISOLABEL:=DU sol_$VERSION}		# default ISO label
	fi
	check_dudir || return		# should be called after check_iso

	# Rest of arguments must be packages.
	collect_packages "$@" || return

	check_prereqs || return

	# Create DU and the (non-bootable) ISO image (if requested).
	create_du && create_nonboot_iso "$DU_OUTDIR"
	if (( i=$? ))
	then
		$RM -rf "$DU_OUTDIR/DU"
		[[ -n "$ISO" ]] && rm -f "$ISO"
	fi
	return $i
}


#
# Starting point for patchmedia subcommand:
#
#	Patch a Solaris install image with the given packages and patches.
#
function patchmedia # <arg> ...
{
	typeset soldir

	process_options "$@" || return
	shift 'MYOPTIND - 1'

	if (( $# == 0 ))
	then
		gettext "Please specify one or more packages or patches.\n"
		usage_short
		return 1
	fi

	# -R option must be specified
	if [[ -z "$MEDIA_ROOT" ]]
	then
		gettext "Please specify Solaris media root (-R option).\n"
		usage_short
		return 1
	fi
	check_media_root || return

	# Get the Solaris directory under $MEDIA_ROOT.
	soldir=$($LS -d $MEDIA_ROOT/Solaris* 2>/dev/null)
	if [[ -z "$soldir" ]]
	then
		gettext "Can't find Solaris directory in $MEDIA_ROOT.\n"
		return 1
	fi

	# Extract the Solaris release number from the Solaris_* directory.
	RELEASE=5.${soldir##*Solaris_}
	check_release || return

	# If user specifies an ISO image to create.
	if [[ -n "$ISO" ]]
	then
		check_iso || return
		${ISOLABEL:=${soldir##*/}}		# default ISO label
	fi

	# Rest of arguments must be packages or patches.
	collect_packages_patches "$@" || return

	# Verify we have some important utilities we need.
	check_prereqs || return

	# Verify there's miniroot file in $MEDIA_ROOT.
	check_miniroot || return

	# Create the ITU directory on the media root, if necessary
	ITUDIR=$MEDIA_ROOT/ITUs
	$MKDIR -p "$ITUDIR" || return

	# The ITU directory might contain multiple driver updates already,
	# each in a separate numbered subdirectory.  So look for the
	# subdirectory with the highest number and we'll add the packages
	# and patches on the next one.
	ITU_COUNTDIR=$($LS -d "$ITUDIR"/+([0-9]) 2>/dev/null |
		$SED 's;.*/;;' | $SORT -rn | $HEAD -1)
	if [[ $ITU_COUNTDIR == *( ) ]]	# ITU_COUNTDIR is a typeset -Zn var
	then
		ITU_COUNTDIR=0
	else
		(( ITU_COUNTDIR += 1 ))
	fi

	unpack_media || return
	add_pkgs && add_patches
	if (( status=$? )) && [[ -s "$LOGFILE" ]]
	then
		echo;
		gettext "A package or patch installation has failed.\n"
		gettext "Messages from pkgadd and patchadd have been saved in $LOGFILE\n"
		return $status
	else
		rm -f "$LOGFILE"
	fi
	print
	repack_media || return
	create_bootable_iso "$MEDIA_ROOT"
}


#
# Starting point for makeiso subcommand:
#
#	Create a bootable ISO image of a Solaris install image.
#
function makeiso # <arg> ..
{
	process_options "$@" || return
	shift 'MYOPTIND - 1'

	if (( $# == 0 ))
	then
		gettext "Please specify the Solaris media root.\n"
		usage_short
		return 1
	elif (( $# > 1 ))
	then
		gettext "Too many arguments supplied.\n"
		usage_short
		return 1
	fi
	MEDIA_ROOT=$1
	check_media_root || return

	# ISO image must be specified.
	if [[ -z "$ISO" ]]
	then
		gettext "Please specify ISO image file (-o option).\n"
		usage_short
		return 1
	fi
	check_iso || return

	# If user doesn't specify ISO label, use the Solaris_* directory name
	# under $MEDIA_ROOT.
	if [[ -z "$ISOLABEL" ]]
	then
		ISOLABEL=$(echo "$MEDIA_ROOT"/Solaris*)
		ISOLABEL=${ISOLABEL##*/}
	fi

	check_prereqs || return
	create_bootable_iso "$MEDIA_ROOT"
}


#
# Main
#
trap cleanup EXIT

# Numbered subdirectories under ITU directory $ITUDIR.
typeset -Z3 ITU_COUNTDIR=0

# Where to unpack a miniroot.
UNPACKED_ROOT=${TMP_DIR}/miniroot

# Reset arrays.
unset PACKAGES PATCHES

DU_OUTDIR=
FORCE=0
ISO=
ISOLABEL=
MEDIA_ROOT=
RELEASE=
SUBCOMMAND=
VERBOSE_LEVEL=0
VERBOSE_OPTS=

if (( $# == 0 ))
then
	usage_long
	return 1
fi
typeset -l SUBCOMMAND=$1			# ignore case
shift

if [[ $SUBCOMMAND != @(makedu|patchmedia|makeiso) ]]
then
	# Be nice: allow some subcommands that cry out "help".
	case "$SUBCOMMAND" in
	*(-)help|*(-)usage|-h|-\?)
		usage_long
		return 0
		;;
	*)
		gettext "Invalid subcommand: $SUBCOMMAND.\n"
		usage_short
		return 1
		;;
	esac
fi

$MKDIR -p "$TMP_DIR" || return
$RM -f "$LOGFILE"

# Run the subcommand.
$SUBCOMMAND "$@"
