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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/filter/postscript/postscript/Makefile
#

include         ../../../Makefile.lp

COMMONDIR=      ../common

TXTFILES =	README

FILES =				\
		aps.ps		\
		banner.ps	\
		baseline.ps	\
		color.ps	\
		dpost.ps	\
		draw.ps		\
		fatcourier.ps	\
		forms.ps	\
		postdaisy.ps	\
		postdmd.ps	\
		postmd.ps	\
		postplot.ps	\
		postprint.ps	\
		posttek.ps	\
		ps.requests	\
		tsol_banner.ps	\
		tsol_separator.ps	\
		tsol_trailer.ps

ROOTPOSTFILES=	$(FILES:%=$(ROOTLIBLPPOST)/%)

.KEEP_STATE:

all:		$(TXTFILES) $(FILES)

install:	all $(ROOTPOSTFILES)

clean clobber strip lint catalog:
