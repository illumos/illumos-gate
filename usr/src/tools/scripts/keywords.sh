#!/bin/sh
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Checks the list of files to make sure that each given file has a SMI
# standard ident string.
#
# It checks that keywords exist, and verifies the string.  By default,
# all allowable forms of keywords (according to the ON documentation)
# are acceptable.  The '-p' option (pedantic) allows only the canonical
# form of keywords. See below for allowable forms.
#
# Use as "keywords filelist" where filelist is the list of plain files.
#
# However, in general, this utility should not need to be directly
# invoked, but instead used through wx(1) -- e.g., `wx keywords'.
#
# Output consists of filenames with expanded, incorrect or missing
# sccs keywords and/or filenames that were not SCCS files.
#
# Exits with status 0 if all files are sccs files and all files have
# unexpanded, correct keywords. Otherwise, exits with a non-zero status.

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

PATH=/usr/bin:/usr/ccs/bin

USAGE="usage: `basename $0` [-p] <filename> ..."

# Canonical form for .c and .h files
CANON_C_H="^#pragma ident	\"\%\Z\%\%\M\%	\%\I\%	\%\E\% SMI\""
# Canonical form for other files
CANON_OTHER="ident	\"\%\Z\%\%\M\%	\%\I\%	\%\E\% SMI\""
STANDARD="ident	\"(\%\Z\%\%\M\%	+\%\I\%|\%W\%)	+\%\E\% SMI\""
EXPANDED="@\(#\).*[ 	]+[1-9]+(\.[0-9]+)+[ 	]+(-[ 	]+)?[0-9][0-9]/[01][0-9]/[0-3][0-9][ 	]+.*(SMI|Sun)"
LIBERAL="(\%\Z\%\%\M\%[ 	]+\%\I\%|\%W\%)[ 	]+\%\E\%[ 	]+.*(SMI|Sun)"

check_file() {
    fname=$1
    bname=$2
    canon_str=$3
    if [ $pedantic -eq 1 ]; then
	egrep -s "$canon_str" $bname
	if [ $? -ne 0 ]; then
	    echo "Incorrect ident string in $fname"
	    exitcode=1
	fi
    elif [ $liberal -eq 1 ]; then
	egrep -s "$LIBERAL" $bname
	if [ $? -ne 0 ]; then
	    egrep -s "$EXPANDED" $bname
	    if [ $? -eq 0 ]; then
		echo "Expanded keywords in $fname"
	    else
		echo "Incorrect ident string in $fname"
	    fi
	    exitcode=1
	fi
    else
	egrep -s "$STANDARD" $bname
	if [ $? -ne 0 ]; then
	    egrep -s "$EXPANDED" $bname
	    if [ $? -eq 0 ]; then
		echo "Expanded keywords in $fname"
	    else
		echo "Incorrect ident string in $fname"
	    fi
	    exitcode=1
	fi
    fi
}

pedantic=0
liberal=0
cwd=`pwd`
exitcode=0
rm -f /tmp/xxx$$ /tmp/kywrds.$$
trap "rm -f /tmp/xxx$$ /tmp/kywrds.$$" 0

while getopts lp c
do
    case $c in
    l)	liberal=1;;
    p)	pedantic=1;;
    \?)	echo $USAGE
	exit 2;;
    esac
done
shift `expr $OPTIND - 1`

for i
do
    dir=`dirname $i`
    file=`basename $i`

    # Try to build the full path to the file argument
    echo $dir | egrep -s '^/'
    if [ ! $? -eq 0 ]; then
        dir=`pwd`/$dir
    fi

    cd $dir

    if [ -f SCCS/s.$file ]; then
	if [ -f SCCS/p.$file ]; then
	    case "$file" in
		*.cxx|*.cc|*.c|*.hh|*.h)
	    	    canon_str="$CANON_C_H";;
		*)
		    canon_str="$CANON_OTHER";;
	    esac
	    check_file $i $file "$canon_str"
	else
	    sccs get -p $file > /dev/null 2>/tmp/xxx$$
	    if [ $? -ne 0 ]; then	   
		echo "Cannot access SCCS information: $i"
		exitcode=1
		continue
	    fi
	    egrep -s "cm7" /tmp/xxx$$
	    if [ $? -eq 0 ]; then
		egrep -s "$EXPANDED" $file
		if [ $? -eq 0 ]; then
		    echo "Expanded keywords in $i"
		else
		    echo "Missing keywords in $i"
		fi
		exitcode=1
	    else
	    	sccs get -p -k $file > /tmp/kywrds.$$ 2>/tmp/xxx$$
		case "$file" in
		    *.cxx|*.cc|*.c|*.hh|*.h)
			canon_str="$CANON_C_H";;
		    *)
			canon_str="$CANON_OTHER";;
		esac
		check_file $i /tmp/kywrds.$$ "$canon_str"
    	    fi
    	fi
    else
    	echo "Not an SCCS file: $i"
    	exitcode=1
    fi
    cd $cwd
done

exit $exitcode
