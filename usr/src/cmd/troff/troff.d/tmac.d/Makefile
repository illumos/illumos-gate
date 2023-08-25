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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# cmd/troff/troff.d/tmac.d/Makefile
#

include 	../../../Makefile.cmd

ROOTTMAC =	$(ROOTSHLIB)/tmac

FILES =		acm.me an ansun ansun.tbl bib \
		chars.me deltext.me e eqn.me  \
		float.me footnote.me index.me local.me m \
		mmn mmt ms.acc ms.cov ms.eqn ms.ref ms.tbl \
		ms.ths ms.toc null.me refer.me s sh.me \
		tbl.me thesis.me tz.map v vgrind

FILEMODE =	644

ROOTFILES =	$(FILES:%=$(ROOTTMAC)/%)

.KEEP_STATE:

all:		$(FILES)

install:	all $(ROOTTMAC) $(ROOTFILES)

$(ROOTTMAC) :
		$(INS.dir)

$(ROOTTMAC)/% :	%
		$(INS.file)

clean clobber lint strip :
