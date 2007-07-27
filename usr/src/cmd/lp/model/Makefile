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
# cmd/lp/model/Makefile
#

include			../Makefile.lp

SUBDIRS =		netpr

PROG =			lp.set		\
			lp.cat		\
			lp.tell		\
			lp.tsol_separator	\
			drain.output

SRCS =			$(PROG:%=%.c)

OBJS =			$(PROG:%=%.o)

MODELS =		standard	\
			netstandard	\
			tsol_standard	\
			tsol_netstandard	\
			tsol_standard_foomatic	\
			tsol_netstandard_foomatic	\
			uri

MISC =			alert.proto


ROOTLIBLPMODEL=		$(ROOTLIBLP)/model
ROOTLIBLPBIN =		$(ROOTLIBLP)/bin

ROOTMISC =		$(MISC:%=$(ROOTLIBLPBIN)/%)
ROOTLPPROG =		$(PROG:%=$(ROOTLIBLPBIN)/%)
ROOTMODELS =		$(MODELS:%=$(ROOTLIBLPMODEL)/%)

CPPFLAGS =		-I$(LPINC) $(CPPFLAGS.master)

# conditional assignments
lp.tell :=			LDLIBS += $(LIBMSG) $(LIBLP)
lp.set drain.output lp.cat :=	LDLIBS += $(LIBLP) -lcurses
lp.tsol_separator :=		LDLIBS += -ltsol

$(ROOTMISC) :=		FILEMODE = 0444

POFILE=			lp_model.po
POFILES=		$(SRCS:%.c=%.po)

.KEEP_STATE:

all:			$(PROG) $(MODELS) $(MISC) $(SUBDIRS)

install:		all .WAIT $(ROOTLPPROG) $(ROOTMODELS) $(ROOTMISC) \
			$(SUBDIRS)

$(ROOTLIBLPMODEL)/% $(ROOTLIBLPBIN)/%:	%
			$(INS.file)

catalog:		$(SUBDIRS) $(POFILE)
			$(CP) $(POFILE) ..

clean:			$(SUBDIRS)
			$(RM) $(OBJS)

clobber:		$(SUBDIRS) clean
			-$(RM) $(PROG) $(CLOBBERFILES)

strip:
			$(STRIP) $(PROG)

lint:
			$(LINT.c) $(SRCS) $(LDLIBS)

$(SUBDIRS) :	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

include		../Makefile.lp.msg

FRC:
