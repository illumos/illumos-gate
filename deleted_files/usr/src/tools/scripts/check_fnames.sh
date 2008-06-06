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

# avoid confusion due to translated output from localized commands
export LC_ALL=C 

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
	echo "usage: $CMD -s synonyms-file -l shared-lib object-file ..." >&2
	$RM -f /tmp/forbid.$$
	exit 1
}

# Add to the list of forbidden names from the shared library
# and its dependencies
examine_library() {
	if [ -f $1 ]
	then
		:
	else
		echo "$CMD: error: -l $1: non-existent file" >&2
		usage
	fi
	if $FILE $1 | $GREP -q 'ELF .* dynamic lib'
	then
		:
	else
		echo "$CMD: error: -l $1: not a shared library" >&2
		usage
	fi

	SUBDIR=
	if $FILE $1 | $GREP -q '64-bit'
	then
		SUBDIR=/64
	fi

	# First the library
	$NM -Dphvx $1 | $GREP -v '^0x0000.*0000 ' >/tmp/match.$$

	# Then its dependencies
	$ELFDUMP -d $1 | $GREP -E 'NEEDED|SUNW_FILTER' |
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
			echo $NEEDED
		fi
	done | $SORT -u |
	while read DEPEND
	do
		$NM -Dphvx $DEPEND | $GREP -v '^0x0000.*0000 '
	done >>/tmp/match.$$

	addr1=""
	name1=""
	while read addr2 trash name2
	do
		if [ "$addr1" = "$addr2" ]
		then
			LIST="$name1"
			while [ "$addr1" = "$addr2" ]
			do
				LIST="$LIST $name2"
				addr1="$addr2"
				name1="$name2"
				read addr2 trash name2
			done
			UNDERBAR=0
			for NAME in $LIST
			do
				case $NAME in
				_etext|_edata|_end) ;;
				_*) UNDERBAR=1 ;;
				esac
			done
			if [ $UNDERBAR -ne 0 ]
			then
				for NAME in $LIST
				do
					case $NAME in
					_*|.*) ;;
					*) echo $NAME ;;
					esac
				done
			fi
		fi
		addr1="$addr2"
		name1="$name2"
	done </tmp/match.$$ >>/tmp/forbid.$$

	$RM -f /tmp/match.$$
}

# Add to the list of forbidden names from the synonyms file
examine_synonyms() {
	if [ -f $1 ]
	then
		:
	else
		echo "$CMD: error: -s $1: non-existent file" >&2
		usage
	fi
	$GREP '^#define' $1 | $GREP -v _COMMON_ |
	while read d NAME trash
	do
		echo $NAME
	done >>/tmp/forbid.$$
}

if [ $# -eq 0 ]
then
	usage
fi

>/tmp/forbid.$$

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

$SORT -u -o /tmp/forbid.$$ /tmp/forbid.$$

# Examine each object file, looking for forbidden names
for file
do
	if $FILE $file | $GREP -q 'ELF.*relocatable'
	then
		LIST="`$NM -uph $file | $GREP -w -f /tmp/forbid.$$`"
		if [ ! -z "$LIST" ]
		then
			echo "$CMD: error: forbidden names found in $file"
			echo "$LIST"
			STATUS=1
		fi
	else
		echo "$CMD: error: $file: not a relocatable object file" >&2
		STATUS=1
	fi
done

$RM -f /tmp/forbid.$$

exit $STATUS
