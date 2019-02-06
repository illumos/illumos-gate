#!/bin/ksh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

#
# Terminal Info Generator
#
# This script generates a static terminfo database for use by mdb.  For each
# of the terminal properties used by mdb_termio.c, this script uses tput(1)
# to determine the value of the given attribute for each specified terminal
# type.  The script produces an ANSI-C source file which contains a static
# array for each terminal type storing the properties.  An additional array
# is then declared containing a list of the terminal types and pointers to
# the previous arrays.  Finally, source code for several terminfo routines
# are included that simply access the arrays and return the saved properties.
#

PATH=/usr/bin; export PATH

PROGNAME=$(basename "$0")

usage()
{
	echo "Usage: $PROGNAME -s skel -t termio [-v] term ..." >&2
	exit 2
}

extract_section()
{
	typeset skel="$1"
	typeset secname="$2"

	nawk <$skel -v name=$secname -v skel=$skel '
	    /\/\* [^ ]* [^ ]* \*\// && $3 == name {
		if ($2 == "BEGIN") {
			printing = 1;
			printf("# %d \"%s\"\n", NR + 1, skel);
		} else {
			printing = 0;
		}
		next;
	    }

	    printing != 0 { print; }
	'
}

verbose=false
termio_c=
terminfo_skel=

while getopts s:t:v name ; do
	case $name in
	    v)
		verbose=true
		;;
	    s)
		terminfo_skel=$OPTARG
		;;
	    t)
		termio_c=$OPTARG
		;;
	    ?)
		usage
		;;
	esac
done
shift $(($OPTIND - 1))

[[ -z "$terminfo_skel" || -z "$termio_c" || $# -eq 0 ]] && usage

termlist=$*
for term in $termlist; do
	tput -T $term init >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "`basename $0`: invalid terminal -- $term" >& 2
		exit 1
	fi
done

# Extract the prologue from the skeleton
extract_section $terminfo_skel PROLOGUE

#
# For each terminal in the terminal list, produce a property definition array
# listing each property we need in mdb_termio.c and its current value.
#
for term in $termlist; do
	#
	# We don't want the compiler to blame the skeleton if it doesn't like
	# the array we generate here, so point the finger elsewhere
	#
	echo "# 1 \"dynamic $term data from tigen\""

	cterm=$(echo "$term" |tr '-' '_')

	$verbose && echo "loading terminfo for $term ... \c" >& 2
	echo "static const termio_attr_t ${cterm}_attrs[] = {"

	sed -n '/termio_attrs\[\] = /,/^}/p' $termio_c | \
	    sed -n \ 's/{ "\([a-z0-9]*\)", \([A-Z_]*\),.*/\1 \2/p' | \
	    while read attr type; do

		case "$type" in
		TIO_ATTR_REQSTR|TIO_ATTR_STR)
			data="\"`tput -T $term $attr | od -bv |
			    sed 's/^[0-9]*//;s/ /\\\\\\\\/g;/^\$/d'`\""
			[ "$data" = '""' ] && data=NULL
			;;
		TIO_ATTR_BOOL)
			tput -T $term $attr
			data=`expr 1 - $?`
			;;
		TIO_ATTR_INT)
			data=`tput -T $term $attr`
			;;
		*)
			echo "`basename $0`: unknown type for $attr: $type" >& 2
			exit 1
		esac
		echo "\t{ \"$attr\", $type, (void *)$data },"
	done

	echo "\t{ NULL, 0, NULL }"
	echo "};\n"

	$verbose && echo "done" >& 2
done

#
# For each terminal in the terminal list, produce an entry in the terminal
# database array linking this terminal to its terminfo property array.
#
echo "# 1 \"dynamic array from tigen\""
echo "static const termio_desc_t termio_db[] = {"
for term in $termlist; do
	cterm=$(echo "$term" |tr '-' '_')
	echo "\t{ \"$term\", ${cterm}_attrs },"
done
echo "\t{ NULL, NULL }\n};"

extract_section $terminfo_skel EPILOGUE

exit 0
