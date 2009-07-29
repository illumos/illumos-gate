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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for cmd/man/src
#

include		../../Makefile.cmd

BINPROG =	man
LIBPROG =	getNAME
LIBSHELL =	makewhatis
LNKPROG =	catman apropos whatis
SGMLUTILDIR = 	util

PROG =		$(BINPROG) $(LIBPROG)

SRCS =		man.c getNAME.c

SHSRCS =	makewhatis.sh

OBJS =		$(SRCS:%.c=%.o)


CLOBBERFILES +=	$(LNKPROG) $(LIBSHELL)

ROOTPROG =	$(BINPROG:%=$(ROOTBIN)/%)
ROOTLIBPROG =	$(LIBPROG:%=$(ROOTLIB)/%)
ROOTLIBSHELL =	$(LIBSHELL:%=$(ROOTLIB)/%)
ROOTLNKPROG =	$(LNKPROG:%=$(ROOTBIN)/%)

# for messaging catalog files
POFILE= src.po
POFILES= $(SRCS:%.c=%.po)

.KEEP_STATE :

all :		$(PROG) $(LIBSHELL) $(LNKPROG) buildsubs

makewhatis :	$$@.sh
		cat $@.sh > $@

buildsubs :		
		cd $(SGMLUTILDIR); pwd; $(MAKE) all

install :	all $(ROOTPROG) $(ROOTLIBPROG)	\
		$(ROOTLIBSHELL) $(ROOTLNKPROG) installsubs

installsubs :		
		cd $(SGMLUTILDIR); pwd; $(MAKE) install

$(ROOTLNKPROG) :	$(ROOTBIN)/man
		-$(RM) $@; $(LN) $(ROOTBIN)/man $@

$(LNKPROG) :	man
		-$(RM) $@; $(LN) man $@

catalog:        $(POFILE)

$(POFILE):      $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@


clean :		sgml_clean

sgml_clean :
		cd $(SGMLUTILDIR); pwd; $(MAKE) clean

clobber :	sgml_clobber

sgml_clobber :
		cd $(SGMLUTILDIR); pwd; $(MAKE) clobber

strip :
		$(STRIP) $(PROG)

lint : 		lint_SRCS

include		../../Makefile.targ
