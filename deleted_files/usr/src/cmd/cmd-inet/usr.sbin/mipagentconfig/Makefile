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
# Copyright (c) 1999,2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/cmd-inet/usr.sbin/mipagentconfig/Makefile
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/cmd-inet/Makefile.cmd-inet

PROG= mipagentconfig

LCLOBJS=addr.o \
	general.o \
	gsp.o \
	utils.o \
	advertisements.o \
	spi.o \
	pool.o \
	mipagentconfig.o

COMOBJS= conflib.o

HDRS=	addr.h \
	advertisements.h \
	general.h \
	gsp.h \
	mipagentconfig.h \
	pool.h \
	spi.h \
	utils.h


OBJS= $(LCLOBJS) $(COMOBJS)

# Currently used only for linting and style checking
SRCS=$(LCLOBJS:%.o=%.c) $(COMOBJS:%.o=$(CMDINETCOMMONDIR)/%.c)

# I18n
POFILE=$(PROG)_prog.po
POFILES=$(LCLOBJS:%.o=%.po)

CPPFLAGS += -I$(CMDINETCOMMONDIR) -D_XOPEN_SOURCE=500 -D__EXTENSIONS__
CLOBBERFILES += $(PROG)

# Only root should be able to run mipagentconfig
FILEMODE= 500

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) *.o

check: $(HDRS:%.h=%.hcheck) $(SRCS:%.c=%.check)

%.hcheck: %.h
	$(DOT_H_CHECK)

%.check: %.c
	$(DOT_C_CHECK)

install: all $(ROOTUSRSBINPROG)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

include $(SRC)/cmd/Makefile.targ

lint: lint_SRCS
