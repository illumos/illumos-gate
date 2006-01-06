#!/bin/ksh
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

CMD=`/usr/bin/basename $0`
ELFDUMP=/usr/ccs/bin/elfdump
EXPR=/usr/bin/expr
FILE=/usr/bin/file
GREP=/usr/xpg4/bin/grep
NM=/usr/ccs/bin/nm
RM=/usr/bin/rm
SED=/usr/bin/sed
SORT=/usr/bin/sort
STATUS=0

usage() {
	echo "usage: $CMD -s synonyms-file -l shared-lib object-file ..."
	$RM -f forbid.$$
	exit 1
}

# Add to the list of forbidden names from the shared library
examine_library() {
	if [ -f $1 ]
	then
		:
	else
		echo "$CMD: error: -l $1: non-existent file"
		usage
	fi
	if $FILE $1 | $GREP -q 'ELF .* dynamic lib'
	then
		:
	else
		echo "$CMD: error: -l $1: not a shared library"
		usage
	fi

	SUBDIR=
	if $FILE $1 | $GREP -q '64-bit'
	then
		SUBDIR=/64
	fi

	# Generate the list of forbidden names from the shared library

	$NM -Dphvx $1 | $GREP -v '^0x0000.*0000 ' >match.$$
	$ELFDUMP -d $1 | $GREP NEEDED >needed.$$
	$ELFDUMP -d $1 | $GREP SUNW_FILTER >>needed.$$

	while read a b c NEEDED
	do
		case $NEEDED in
		/*)	;;
		*)	NEEDED=/usr/lib${SUBDIR}/$NEEDED ;;
		esac
		if [ -f ${ROOT}${NEEDED} ]
		then
			NEEDED=${ROOT}${NEEDED}
		fi
		if [ -f "$NEEDED" ]
		then
			$NM -Dphvx $NEEDED |
			$GREP -v '^0x0000.*0000 ' >>match.$$
		fi
	done <needed.$$

	addr1=""
	name1=""
	while read addr2 trash name2
	do
		if [ "$addr1" = "$addr2" ]
		then
			echo "$name1"
			while [ "$addr1" = "$addr2" ]
			do
				echo "$name2"
				addr1="$addr2"
				name1="$name2"
				read addr2 trash name2
			done
		fi
		addr1="$addr2"
		name1="$name2"
	done <match.$$ | $GREP -v '^[^\.]' >>forbid.$$

	$RM -f match.$$ needed.$$
}

# Add to the list of forbidden names from the synonyms file
examine_synonyms() {
	if [ -f $1 ]
	then
		:
	else
		echo "$CMD: error: -s $1: non-existent file"
		usage
	fi
	$GREP '^#define' $1 | $GREP -v _COMMON_ |
	while read d NAME trash
	do
		echo $NAME
	done >>forbid.$$
}

if [ $# -eq 0 ]
then
	usage
fi

>forbid.$$

GOT_LIB_SYN=0
while getopts l:s: ARG
do
	case $ARG in
	l)	examine_library $OPTARG
		GOT_LIB_SYN=1
		;;
	s)	examine_synonyms $OPTARG
		GOT_LIB_SYN=1
		;;
	\?)	usage
		;;
	esac
done
shift `$EXPR $OPTIND - 1`

if [ $GOT_LIB_SYN -eq 0 -o $# -eq 0 ]
then
	usage
fi

$SORT -u -o forbid.$$ forbid.$$

# Examine each object file, looking for forbidden names
for file
do
	if $FILE $file | $GREP -q 'ELF.*relocatable'
	then
		LIST="`$NM -uph $file | $GREP -w -f forbid.$$`"
		if [ ! -z "$LIST" ]
		then
			echo "$CMD: error: forbidden names found in $file"
			echo "$LIST"
			STATUS=1
		fi
	else
		echo "$CMD: error: $file: not a relocatable object file"
		STATUS=1
	fi
done

$RM -f forbid.$$

exit $STATUS
