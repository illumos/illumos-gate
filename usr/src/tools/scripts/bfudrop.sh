#! /usr/bin/ksh -p
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Create a set of BFU archives for posting, then deliver them as a
# tarball, including binary license files.
#
# usage: bfudrop [-n] open-proto closed-bins build-id
# -n			extract non-debug closed binaries.
#			(open-proto and build-id are not modified.)
# open-proto	absolute path to open-only proto area.
# closed-bins	name of closed-bins tarball (bzipped, in $CODEMGR_WS)
# build-ID		identifier for the archives, e.g.,
#			"nightly-osol".
#

usage="bfudrop [-n] open-proto closed-bins build-ID"

function fail {
	print -u2 "bfudrop: $@"
	exit 1
}

[[ -n "$SRC" ]] || fail "SRC must be set."
[[ -n "$CODEMGR_WS" ]] || fail "CODEMGR_WS must be set."
[[ -n "$CPIODIR" ]] || fail "CPIODIR must be set."

#
# Directory that we assemble everything in.  Includes these
# subdirectories:
# tmp			scratch directory
# root_$MACH		combined proto area
# archives-<build-ID>	copy of archives plus license files
#
stagedir=$(mktemp -dt bfudropXXXXX)

[[ -n "$stagedir" ]] || fail "can't create staging directory."

scratchdir="$stagedir/tmp"
cpio_log="$stagedir/cpio.log"

#
# Wrapper over cpio to filter out "NNN blocks" messages.
#
function cpio_filt {
	integer cpio_stat

	cpio "$@" > "$cpio_log" 2>&1
	cpio_stat=$?
	cat "$cpio_log" | awk '$0 !~ /[0-9]+ blocks/ { print }'
	return $cpio_stat
}

#
# Generate README.BFU-ARCHIVES.$MACH from boilerplate and the contents
# of the bfu archives.
# usage: cd archivedir; mkreadme destdir
#
function mkreadme {
	destdir="$1"
	readme="$destdir/README.BFU-ARCHIVES.$MACH"
	sed -e s/@ISA@/$MACH/ -e s/@DELIVERY@/BFU-ARCHIVES/ \
	    "$SRC/tools/opensolaris/README.binaries.tmpl" > "$readme"
	for f in *; do
		print "==== $f ====" >> "$readme"
		#
		# The cpio table of contents includes directories, and
		# we just want files.  So unpack the cpio file into a
		# temp directory, do a find(1) to get the table of
		# contents, and remove the temp directory.
		#
		mkdir -p "$scratchdir" || fail "can't create $scratchdir."
		case $f in
		*.gz)	cat=gzcat;;
		*.Z)	cat=zcat;;
		*.bz2)	cat=bzcat;;
		*)	cat=cat;;
		esac
		if ! $cat $f | (cd "$scratchdir"; cpio_filt -id); then
			fail "can't get contents for $f"
		fi
		#
		# "find *" will miss dot files, but we don't expect
		# any.  "find ." would catch them, but we'd have to
		# clean up the resulting list (remove the "./").
		#
		(cd "$scratchdir"; find * -type f -print) | sort >> "$readme"
		rm -rf "$scratchdir"
	done
}

nondebug=n
while getopts n flag; do
	case $flag in
	n)
		nondebug=y
		;;
	?)
		print -u2 "usage: $usage"
		exit 1
		;;
	esac
done
shift $(($OPTIND - 1))

if [[ $# -ne 3 ]]; then
	print -u2 "usage: $usage"
	exit 1
fi
srcroot="$1"
closedtb="$2"
build="$3"
subdir="archives-$build"

cpioparent="$(dirname $CPIODIR)"
export CPIODIR="$cpioparent/$build"

[[ -n "$MACH" ]] || MACH=$(uname -p)
export MACH
tarfile="$CODEMGR_WS/on-bfu-$build.$MACH.tar"

newproto="$stagedir/root_$MACH"

cd "$CODEMGR_WS"

[[ -d "$srcroot" ]] || fail "can't find $srcroot."
[[ -f "$closedtb" ]] || fail "can't find $closedtb."

#
# Copy the source proto area to a temp area and unpack the closed
# binaries on top.  The source proto area is left alone so as not to
# break future incremental builds.
#

mkdir -p "$newproto" || fail "can't create $newproto."
(cd "$srcroot"; find . -depth -print | cpio_filt -pdm "$newproto")
[[ $? -eq 0 ]] || fail "can't copy original proto area."

mkdir -p "$scratchdir" || fail "can't create $scratchdir"
(cd "$scratchdir"; bzcat "$CODEMGR_WS/$closedtb" | tar xf -)
[[ $? -eq 0 ]] || fail "can't unpack closed binaries."
closed_root="$scratchdir/closed/root_$MACH"
[[ "$nondebug" = y ]] && closed_root="$closed_root-nd"
if [[ ! -d "$closed_root" ]]; then
	fail "can't find $(basename $closed_root) in closed binaries."
fi
(cd "$closed_root"; find . -depth -print | cpio_filt -pdmu "$newproto")
[[ $? -eq 0 ]] || fail "can't copy closed binaries."
rm -rf "$scratchdir"

#
# Generate the actual archives.
#

ROOT="$newproto" makebfu

#
# Bundle up the archives and license files.
#

mkdir -p "$stagedir/$subdir/$MACH" || \
    fail "can't create $stagedir/$subdir/$MACH."

archvdir=$CPIODIR
[[ -d "$archvdir" ]] || fail "can't find $archvdir."

# copy archives
(cd "$archvdir"; tar cf - .) | (cd "$stagedir/$subdir/$MACH"; tar xf -)

# Insert binary license files.
cp -p "$SRC/tools/opensolaris/BINARYLICENSE.txt" "$stagedir/$subdir" || \
    fail "can't add BINARYLICENSE.txt"
(cd "$archvdir"; mkreadme "$stagedir/$subdir") || exit 1
cp -p "$CODEMGR_WS/THIRDPARTYLICENSE.BFU-ARCHIVES" "$stagedir/$subdir" || \
    fail "can't add THIRDPARTYLICENSE.BFU-ARCHIVES."

(cd "$stagedir"; tar cf "$tarfile" "$subdir") || fail "can't create $tarfile."
bzip2 -f "$tarfile" || fail "can't compress $tarfile".

rm -rf "$stagedir"

exit 0
