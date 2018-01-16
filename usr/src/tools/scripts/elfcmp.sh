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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
# elfcmp - compare significant sections in two ELF files
#
# usage: elfcmp [-v] [-S] [-s section ...] <f1> <f2>
#

VERBOSE=0
SECTIONLIST=""
SIGNING_CHECK=0
ERRORS=0

usage() {
	echo 'Usage: elfcmp [-v] [-S] [-s section ...] <f1> <f2>' 1>&2
	exit 1
}

while [[ $# > 0 ]]
do
	case "$1" in
	-v)
		VERBOSE=1
		;;
	-s)
		SECTIONLIST="$2"
		shift
		;;
	-S)
		SIGNING_CHECK=1
		;;
	-*)
		usage
		;;
	*)
		break
		;;
	esac
	shift
done

if [[ $# != 2 ]]
then
	usage
fi

TMP1=/tmp/elfcmp.1.$$
TMP2=/tmp/elfcmp.2.$$
trap "rm -f $TMP1 $TMP2" EXIT HUP INT QUIT PIPE TERM

list_sections() {
	dump -h "$1" | grep '\[[0-9]' | awk '{print $7}'
}

list_alloc_sections() {
	dump -hv "$1" | grep '\[[0-9]' | awk '$3 ~ /A/ {print $4, $5, $6, $7}'
}

signing_filter() {
	/usr/bin/grep -v -e \\$SHSTRTAB -e \\.SUNW_signature
}
	
# get section lists for both files into temp files

if [[ "$SECTIONLIST" = "" ]]
then
	if [[ $SIGNING_CHECK = 1 ]]
	then
		SHSTRNDX=`dump -f "$1" | awk '{if (NR==11) print $5}'`
		SHSTRTAB=`dump -h "$1" | grep "^\\[$SHSTRNDX\\]" | \
			awk '{print $7}'`
		FILTER=signing_filter
	else
		FILTER=cat
	fi

	list_sections "$1" | $FILTER | sort >$TMP1
	list_sections "$2" | $FILTER | sort >$TMP2
else
	echo "$SECTIONLIST" >$TMP1
	echo "$SECTIONLIST" >$TMP2
fi

# determine and print which ones aren't in both of the input files

NOT_IN_1=$(comm -13 $TMP1 $TMP2)
if [[ ! -z "$NOT_IN_1" ]]
then
	echo "Section(s) $NOT_IN_1 not in $1"
	(( ERRORS += 1 ))
fi
NOT_IN_2=$(comm -23 $TMP1 $TMP2)
if [[ ! -z "$NOT_IN_2" ]]
then
	echo "Section(s) $NOT_IN_2 not in $2"
	(( ERRORS += 1 ))
fi

# for all the sections which *are* common, do the following

for s in $(comm -12 $TMP1 $TMP2)
do
	dump -s -n $s "$1" | sed '/:/d' >$TMP1
	dump -s -n $s "$2" | sed '/:/d' >$TMP2
	if cmp -s $TMP1 $TMP2
	then
		if [[ $VERBOSE = 1 ]]
		then
			echo "Section $s is the same"
		fi
	else
		echo "Section $s differs"
		if [[ $VERBOSE = 1 ]]
		then
			dump -sv -n $s "$1" | sed '/:/d' >$TMP1
			dump -sv -n $s "$2" | sed '/:/d' >$TMP2
			diff -c $TMP1 $TMP2
		fi
		(( ERRORS += 1 ))
	fi
done

# verify that allocated objects have not moved
# only applies to signed objects with a program header

if [[ $SIGNING_CHECK = 1 ]]
then
	HDR=$(dump -op $1 | wc -l)
	if [[ $HDR -gt 2 ]]
	then
		list_alloc_sections "$1" | sort >$TMP1
		list_alloc_sections "$2" | sort >$TMP2
		if cmp -s $TMP1 $TMP2
		then
			if [[ $VERBOSE = 1 ]]
			then
				echo "Allocated sections are the same"
			fi
		else
			echo "Allocated section(s) changed"
			if [[ $VERBOSE = 1 ]]
			then
				diff -c $TMP1 $TMP2
			fi
			(( ERRORS += 1 ))
		fi
	fi
fi

exit $ERRORS
