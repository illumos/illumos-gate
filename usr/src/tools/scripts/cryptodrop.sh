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

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Create a tarball with crypto binaries.
#

usage="cryptodrop [-n] result-path"

isa=`uname -p`

function fail {
	print -u2 "cryptodrop: $@"
	exit 1
}

[[ -n "$ROOT" ]] || fail "ROOT must be set."
# Verify below (after adjusting for -n) that $ROOT exists, is a directory.
[[ -n "$SRC" ]] || fail "SRC must be set."
[[ -d "$SRC" ]] || fail "SRC ($SRC) is not a directory."
[[ -n "$CODEMGR_WS" ]] || fail "CODEMGR_WS must be set."
[[ -d "$CODEMGR_WS" ]] || fail "CODEMGR_WS ($CODEMGR_WS) is not a directory."

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
# Create the README from boilerplate and the contents of the closed
# binary tree.
#
# usage: mkreadme targetdir
#
function mkreadme {
	typeset targetdir="$1"
	typeset readme="README.CRYPTO-BINARIES.$isa"

	sed -e s/@ISA@/$isa/ -e s/@DELIVERY@/CRYPTO-BINARIES/ \
	    "$SRC/tools/opensolaris/README.binaries.tmpl" > "$targetdir/$readme"
	(cd "$targetdir"; find "$rootdir" -type f -print | \
	    sort >> "$targetdir/$readme")
}

nondebug=n
while getopts n flag; do
	case $flag in
	n)
		nondebug=y
		if [ "$MULTI_PROTO" = yes ]; then
			export ROOT="$ROOT-nd"
		fi
		;;
	?)
		print -u2 "usage: $usage"
		exit 1
		;;
	esac
done
shift $(($OPTIND - 1))

if [[ $# -ne 1 ]]; then
	print -u2 "usage: $usage"
	exit 1
fi
[[ -d "$ROOT" ]] || fail "ROOT ($ROOT) is not a directory."

tarfile="$1"

if [[ "$nondebug" = n ]]; then
	rootdir="root_$isa"
else
	rootdir="root_$isa-nd"
fi

tmpdir=$(mktemp -dt cryptodropXXXXX)
[[ -n "$tmpdir" ]] || fail "could not create temporary directory."
tmproot="$tmpdir/proto/$rootdir"
mkdir -p "$tmproot" || exit 1
cpio_log="$tmpdir/cpio.log"
filelist="$tmpdir/files"

#
# Copy the crypto binaries into a temp directory.  This is a bit messy
# because we want to preserve the permissions of intermediate
# directories without including all the contents of those
# directories.
#

# Echo all the parent directories of the given file.
function alldirs {
	d=$(dirname "$1")
	while [ "$d" != . ]; do
		echo $d
		d=$(dirname "$d")
	done
}

findcrypto "$SRC/tools/codesign/creds" | awk '{ print $2 }' > "$filelist"
#
# Both alldirs and the cpio -p invocation assume that findcrypto only
# produces relative paths.
#
for f in $(cat "$filelist"); do
	if [[ "$f" = /* ]]; then
		fail "findcrypto produced absolute path ($f)"
	fi
done
for f in $(cat "$filelist"); do
	echo "$f"
	alldirs "$f"
done | sort -u | (cd "$ROOT"; cpio_filt -pdm "$tmproot")
[[ $? -eq 0 ]] || fail "could not copy crypto files."

rm -f "$cpio_log" "$filelist"

#
# Insert binary license files.
#
cp -p "$SRC/tools/opensolaris/BINARYLICENSE.txt" "$tmpdir/proto" || \
    fail "could not add BINARYLICENSE.txt"
mkreadme "$tmpdir/proto" || exit 1
cp -p "$CODEMGR_WS/THIRDPARTYLICENSE.ON-CRYPTO" "$tmpdir/proto" || \
    fail "could not add THIRDPARTYLICENSE.ON-CRYPTO."

(cd "$tmpdir"; tar cf "$tarfile" proto) || fail "could not create $tarfile."
bzip2 -f "$tarfile" || fail "could not compress $tarfile".

rm -rf "$tmpdir"

exit 0
