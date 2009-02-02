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

PROG =		idmap
CLIENTOBJS =	idmap.o idmap_engine.o
# idmap_clnt.o
CLIENTSRCS =	$(CLIENTOBJS:%.o=%.c)
POFILES = 	$(CLIENTOBJS:.o=.po)
OBJS =		$(CLIENTOBJS)
SRCS =		$(CLIENTSRCS)
IDMAP_PROT_DIR =        $(SRC)/head/rpcsvc

include ../../Makefile.cmd

POFILE = 	$(PROG)_all.po
LDLIBS +=	-lidmap
FILEMODE =	0555
GROUP =		bin

INCS += -I. -I../../../lib/libidmap/common -I$(IDMAP_PROT_DIR)

$(OBJS) :=	CPPFLAGS += $(INCS) -D_REENTRANT
$(POFILE) :=	CPPFLAGS += $(INCS)

lint_SRCS :=	CPPFLAGS += $(INCS)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -g -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

LINTFLAGS += -erroff=E_NAME_DEF_NOT_USED2

include ../../Makefile.targ


