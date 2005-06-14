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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/wbem/provider/tools/rds/Makefile
#
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#


PROG = rds
OBJS = rds.o rdutil.o rdfile.o rdtable.o rdkstat.o rdimpl.o rdprot.o prtelement.o
POFILES = $(OBJS:.o=.po)
CLOBBERFILES = $(POFILE) $(POFILES)

include $(SRC)/cmd/wbem/Makefile.cmd

POFILE = prds.po

.KEEP_STATE:

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)


all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint
test	:=	TARGET = test

all:		$(WBEMTOOLDIRS) $(SUBDIRS)
clean:		$(SUBDIRS)
clobber:	$(SUBDIRS)
lint:		$(SUBDIRS)
test:		$(SUBDIRS)

install: all $(SUBDIRS)
	-$(RM) $(ROOTWBEMPROG)
	-$(LN) $(ISAEXEC) $(ROOTWBEMPROG)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

FRC:

include $(SRC)/cmd/Makefile.targ

