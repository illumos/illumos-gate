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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/filter/postscript/font/devpost/charlib/Makefile
#

include			../../../../../Makefile.lp

CHARFILES =		12 14 34 Fi Fl L1 Lb		\
			Sl bx ci ff lc lf lh	\
			ob rc rf rh sq
MAPFILES =		L1.map Lb.map
TXTS =			BRACKETS_NOTE README
FILES =			$(CHARFILES) $(MAPFILES) $(TXTS)

ROOTCHARLIB =		$(ROOT)/usr/lib/font/devpost/charlib

ROOTFILES =		$(FILES:%=$(ROOTCHARLIB)/%)

FILEMODE =		0444

.KEEP_STATE:

all:			$(FILES)

# because of its name, the file ~= is a special case
#
install:		all $(ROOTCHARLIB) $(ROOTFILES)
			$(RM) $(ROOTCHARLIB)/~=
			$(INS) -m $(FILEMODE) -f $(ROOTCHARLIB) ~=
			$(RM) $(ROOTCHARLIB)/'~'
			$(LN) $(ROOTCHARLIB)/~= $(ROOTCHARLIB)/'~'

$(ROOTCHARLIB):
			$(INS.dir)

$(ROOTCHARLIB)/% :	%
			$(INS.file)

clean clobber strip lint :

FRC:
