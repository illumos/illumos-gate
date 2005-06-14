#!/bin/sh
#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#############################################################################
#
#	sgml2roff
#       adapted from docbook-to-man.sh
#
#############################################################################
# 
# Copyright (c) 1996 X Consortium
# Copyright (c) 1996 Dalrymple Consulting
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# X CONSORTIUM OR DALRYMPLE CONSULTING BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# Except as contained in this notice, the names of the X Consortium and
# Dalrymple Consulting shall not be used in advertising or otherwise to
# promote the sale, use or other dealings in this Software without prior
# written authorization.
# 
#############################################################################
#
# Written 5/29/96 by Fred Dalrymple
#
#############################################################################

# ***** change the following paths if your installation of nsgmls and / or
# ***** DocBook isn't into the default places.

ROOT=/usr
SGMLS=$ROOT/lib/sgml
SUPPORT=$ROOT/share/lib/sgml/locale
LOCALE_DIR=${LC_ALL:-${LC_MESSAGES:-${LANG:-C}}}

if [ $LOCALE_DIR = "en_US" ]
then
    LOCALE_DIR=C
fi

if [ ! -d $SUPPORT/$LOCALE_DIR ]
then
	LOCALE_DIR=C
fi

DTDS=$SUPPORT/$LOCALE_DIR/dtds
TPTFILES=$SUPPORT/$LOCALE_DIR/transpec

# Everything below this line should be pretty standard and not require
# modification.

PARSER=$SGMLS/nsgmls
INSTANT=$SGMLS/instant
INSTANT_OPT=-d

CATALOG=$DTDS/catalog
DECL=$DTDS/solbook.dcl

if [ $# -ne 1 ]; then
	echo "usage:  sgml2roff <manpage>"
	exit 1
fi

# Is it an SGML man page? If not is it a shadow?
#
if grep -i '<refentry[ >]' < $1 >/dev/null 2>&1;
then
   echo "'"'\" te';	\
   $PARSER -gl -m$CATALOG -E0 $1 2>/dev/null | \
   $INSTANT $INSTANT_OPT \
    -c$TPTFILES/roff.cmap -s$TPTFILES/roff.sdata -t$TPTFILES/docbook-to-man.ts
else
   if  head -10 $1 | fgrep SHADOW_PAGE >/dev/null 2>&1
   then
	# This is a shadow man page.
	# Figure out the real page, and kick out stub pointing to it

	MASTER=`nawk '/SYSTEM/ {gsub("\"","",$4);gsub(">","",$4);print $4}' \
	    < $1`
	echo ".so `dirname $1`/$MASTER"
   fi
fi
