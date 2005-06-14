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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG= file
XPG4PROG= file
MAGIC= magic

ELFCAP=	$(SRC)/common/elfcap

LOBJS=	file.o magicutils.o
OBJS=	$(LOBJS) elfcap.o
XPG4OBJS= $(OBJS:%.o=xpg4_%.o)
SRCS=	$(LOBJS:%.o=%.c) $(ELFCAP)/elfcap.c

include ../Makefile.cmd

POFILE= file_all.po
POFILES= $(LOBJS:%.o=%.po)

LDLIBS += -lelf
CPPFLAGS += -DCAP_UPPERCASE -I$(ELFCAP)
$(XPG4) := CFLAGS += -DXPG4

ROOTETCMAGIC= $(MAGIC:%=$(ROOTETC)/%)

$(ROOTETCMAGIC) :=	FILEMODE =	$(LIBFILEMODE)

.PARALLEL:	$(OBJS) $(XPG4OBJS) $(POFILES)

.KEEP_STATE:

all: $(PROG) $(XPG4) $(MAGIC)

$(PROG) : $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG4) : $(XPG4OBJS)
	$(LINK.c) $(XPG4OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

xpg4_%.o:	%.c
	$(COMPILE.c) -o $@ $<

elfcap.o:	$(ELFCAP)/elfcap.c
	$(COMPILE.c) -o $@ $(ELFCAP)/elfcap.c

xpg4_elfcap.o:	$(ELFCAP)/elfcap.c
	$(COMPILE.c) -o $@ $(ELFCAP)/elfcap.c

$(POFILE):	$(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTETCMAGIC)

clean:
	$(RM) $(OBJS) $(XPG4OBJS)

lint: lint_SRCS

include ../Makefile.targ
