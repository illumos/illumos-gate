#!/usr/bin/ksh -p
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
# Given a machine-optimal patch makeup table (see ctfcvtptbl), this program
# will allow the build process to determine the following:
#
#   * The patch ID associated with a given module
#   * The KU required by the patch associated with a given module
#   * The patch ID and location of the genunix module preceding the genunix
#     module currently being built.
#

PROGNAME=$(basename "$0")

usage()
{
	echo "Usage: $PROGNAME [-nr] [-o outfmt] [-b build_type] -t table" \
	    "module_path" >&2
}

die()
{
	echo "$1" >&2
	exit 1
}

outfmt="patch,ku"
notfoundok=0
relative=0
build_type=debug32
err=0
while getopts b:lno:rt: c ; do
	case $c in
	    b)
		build_type="$OPTARG"
		;;
	    n)
		notfoundok=1
		;;
	    o)
		outfmt="$OPTARG"
		;;
	    r)
		relative=1
		;;
	    t)
		table="$OPTARG"
		;;
	    \?)
		err=1
		;;
	esac
done
shift `expr $OPTIND - 1`

if [[ $err -eq 1 || $# -ne 1 || -z "$table" ]] ; then
	usage
	exit 2
fi

print_garpath=0
print_ku=0
print_patch=0
print_lastgu=0
for word in $(echo "$outfmt" |tr ',' ' ') ; do
	case $word in
	    garpath)
		print_garpath=1
		;;
	    ku)
		print_ku=1
		;;
	    lastgu)
		print_lastgu=1
		;;
	    patch)
		print_patch=1
		;;
	    \?)
		usage
		exit 2
	esac
done

module="$1"
shift

if [[ ! -f "$table" ]] ; then
	die "$PROGNAME: Cannot open $table"
fi

head -1 "$table" |sed -e 's/^\([^=]*\)=/\1 /' |read garkw garpath

if [[ "$garkw" != "GENUNIX_ARCHIVE" || -z "$garpath" ]] ; then
	die "$PROGNAME: $table is not a machine-optimal patch table" >&2
fi

if [[ $relative -eq 1 ]] ; then
	crd=$(pwd |sed -e 's:^.*usr/src/uts::')
	module=$(echo "$crd/$module" |sed -e 's://*:/:g')
fi

fgrep "$module" "$table" |read junk patch ku

if [[ -z "$patch" ||
    "$(expr "$patch" : '[0-9]\{6\}-[0-9][0-9]')" -ne 9 ]] ; then
	if [[ "$notfoundok" -eq 1 ]] ; then
		patch="-"
	else
		die "$PROGNAME: Cannot find patch for $module" >&2
	fi
fi

if [[ -z "$ku" ]] ; then
	ku="-"
fi

# Output

space=""
if [[ $print_patch -eq 1 ]] ; then
	echo "$space$patch\c"
	space=" "
fi
if [[ $print_ku -eq 1 ]] ; then
	echo "$space$ku\c"
	space=" "
fi
if [[ $print_garpath -eq 1 ]] ; then
	echo "$space$garpath\c"
	space=" "
fi
if [[ $print_lastgu -eq 1 ]] ; then
	suffix=
	if expr $build_type : '.*64' >/dev/null ; then
		if [ `uname -p` = "sparc" ] ; then
			suffix=/sparcv9
		else
			suffix=/amd64
		fi
	fi
	echo "$space$garpath/$ku$suffix/genunix\c"
	space=" "
fi
[[ -n "$space" ]] && echo

return 0
