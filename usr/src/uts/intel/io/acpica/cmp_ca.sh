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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

#
# Set this to the fully-qualified path to the ACPI CA GIT directory
#
ACDIR=/tmp/acpica-unix-20091112

ACSRC=$ACDIR
ACINC=$ACDIR/include

DIFF="diff -w"

#
# Use which_scm to get the current WS path
#
which_scm | read WS_SCM WSDIR

WSSRC=usr/src/uts/intel/io/acpica
WSHDR=usr/src/uts/intel/sys/acpi
ACFILES=/tmp/$$.acfiles
SRCDIRS="debugger \
	disassembler \
	dispatcher \
	events \
	executer \
	hardware \
	namespace \
	parser \
	resources \
	tables \
	utilities"

#
#
#
cd $ACSRC ; find  $SRCDIRS -type f  > $ACFILES ; cd -
for i in `<$ACFILES`
do
    if [[ ! -a $WSDIR/$WSSRC/$i ]]
    then
	SRCNEW=$SRCNEW\ $i
    else
	if (! $DIFF $WSDIR/$WSSRC/$i $ACSRC/$i > /dev/null )
	then
	    SRCCHG=$SRCCHG\ $i
	fi
    fi
done

#
#
#
cd $ACINC ; find . -type f  > $ACFILES ; cd -
for i in `<$ACFILES`
do
    if [[ ! -a $WSDIR/$WSHDR/$i ]]
    then
	HDRNEW=$HDRNEW\ $i
    else
	if (! $DIFF $WSDIR/$WSHDR/$i $ACINC/$i > /dev/null )
	then
		HDRCHG=$HDRCHG\ $i
	fi
    fi
done

cd $WSDIR
for i in $SRCCHG
do
    targ=$WSSRC/$i
    cp $ACSRC/$i $targ
done

for i in $SRCNEW
do
    targ=$WSSRC/$i
    cp $ACSRC/$i $targ
    chmod +w $targ
    hg add $targ
done

for i in $HDRCHG
do
    targ=$WSHDR/$i
    cp $ACINC/$i $targ
done

for i in $HDRNEW
do
    targ=$WSHDR/$i
    cp $ACINC/$i $targ
    chmod +w $targ
    hg add $targ
done

if (! $DIFF $WSDIR/$WSSRC/changes.txt $ACDIR/changes.txt > /dev/null )
then
    targ=$WSSRC/changes.txt
    cp $ACDIR/changes.txt $targ
fi
cd -

echo New source files:
echo $SRCNEW
echo New header files:
echo $HDRNEW
