#! /bin/sh -f
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
#	Copyright (c) 1989 AT&T
#	  All Rights Reserved
#
# Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
#

#	COMMON LORDER
#
#
if [ -z "$TMPDIR" ]
then
	TDIR="/tmp"
else
	TDIR=$TMPDIR
fi
trap "rm -f $TDIR/$$symdef $TDIR/$$symref $TDIR/$$tmp; exit"  1 2 13 15
PFX=
WHERE=/usr/bin

USAGE="Usage: ${PFX}lorder file ..."
for i in "$@"
do
	case "$i" in
	-*)	echo "$USAGE";
		exit 2;;
	esac

	if [ ! -r "$i" ]
	then
		echo "${PFX}lorder: $i: cannot open"
		exit 2;
	fi
done

case $# in
0)	echo "$USAGE"
	exit 2;;
1)	case $1 in
	*.o)	set $1 $1
	esac
esac

#	The following sed script is commented here.
#	The first three expressions in the sed script
#	insures that we only have lines
#	that contain file names and the external
#	declarations associated with each file.
#	The next two parts of the sed script put the pattern
#	(in this case the file name) into the hold space
#	and creates the "filename filename" lines and
#	writes them out. The first part is for .o files,
#	the second is for .o's in archives.
#	The last 2 sections of code are exactly alike but
#	they handle different external symbols, namely the
#	symbols that are defined in the text section, data section, bss
#	section or common symbols and symbols 
#	that are referenced but not defined in this file.
#	A line containing the symbol (from the pattern space) and 
#	the file it is referenced in (from the hold space) is
#	put into the pattern space.
#	If its text, data, bss or common it is written out to the 
#	symbol definition (symdef) file, otherwise it was referenced 
#	but not declared in this file so it is written out to the
#	symbol referenced (symref) file.
#
#
${WHERE}/${PFX}nm -p $* 2>$TDIR/$$tmp | sed -e '/^[ 	]*$/d' -e '
	/^[0-9]* R $/d
	/ [a-zFLS] /d
	/[^]]:$/{
		s/://
		h
		s/.*/& &/
		p
		d
	}
	/]:$/{
		s/]://
		s/^.*\[//
		h
		s/.*/& &/
		p
		d
	}
	/ [TDBNCAR] /{
		s/^.* [TDBNCAR] //
		G
		s/\n/ /
		w '$TDIR/$$symdef'
		d
	}
	/ U /{
		s/^.* U //
		G
		s/\n/ /
		w '$TDIR/$$symref'
		d
	}
'
if [ -s $TDIR/$$tmp ]
then
	sed -e "s/^${PFX}nm:/${PFX}lorder:/" < $TDIR/$$tmp >&2
	rm -f $TDIR/$$symdef $TDIR/$$symref $TDIR/$$tmp
	exit 1
fi
sort $TDIR/$$symdef -o $TDIR/$$symdef
sort $TDIR/$$symref -o $TDIR/$$symref
join $TDIR/$$symref $TDIR/$$symdef | sed 's/[^ ]* *//'
rm -f $TDIR/$$symdef $TDIR/$$symref $TDIR/$$tmp
