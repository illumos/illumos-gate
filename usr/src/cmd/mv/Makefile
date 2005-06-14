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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/mv/Makefile
#

PROG=		mv
XPG4PROG=	mv
OBJS=           mv.o
CPFILE=		cp
LNFILE=		ln
XPG4OBJS=	$(OBJS:%.o=xpg4_%.o)
SRCS=		$(OBJS:%.o=%.c)
ROOTLINKS= $(ROOTBIN)/$(CPFILE) $(ROOTBIN)/$(LNFILE)
ROOTXPG4LINKS= $(ROOTXPG4BIN)/$(CPFILE) $(ROOTXPG4BIN)/$(LNFILE)

include ../Makefile.cmd

clean $(XPG4)	:= OBJS += values-xpg4.o

CLOBBERFILES += $(CPFILE) $(LNFILE)
CFLAGS	+=	$(CCVERBOSE)
$(XPG4) := CFLAGS += -DXPG4
LINTFLAGS += -DXPG4
XGETFLAGS += -a -x mv.xcl
CPPFLAGS += -D_FILE_OFFSET_BITS=64
LINTFLAGS += -DXPG4

lint :=	LDLIBS += -lcmdutils -lavl
$(PROG) := LDLIBS += $(ZLAZYLOAD) -lcmdutils -lavl $(ZNOLAZYLOAD)
$(XPG4) := LDLIBS += $(ZLAZYLOAD) -lcmdutils -lavl $(ZNOLAZYLOAD)

.KEEP_STATE:

all:	$(PROG) $(CPFILE) $(LNFILE) $(XPG4)



$(PROG):	$$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(XPG4):	$$(XPG4OBJS)
	$(LINK.c) -o $@ $(XPG4OBJS) $(LDLIBS)
	$(POST_PROCESS)

xpg4_%.o:	%.c
	$(COMPILE.c) -o $@ $<

%values-xpg4.o: ../../lib/common/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/common/common/values-xpg4.c

$(CPFILE):	$(PROG)
	@$(RM) $(CPFILE); $(LN) $(PROG) $(CPFILE)

$(LNFILE):	$(PROG)
	@$(RM) $(LNFILE); $(LN) $(PROG) $(LNFILE)

install: all $(ROOTXPG4PROG) $(ROOTLINKS) $(ROOTXPG4LINKS)

$(ROOTLINKS):	$(ROOTPROG)
	$(RM) $@
	$(LN) $(ROOTPROG) $@

$(ROOTXPG4LINKS):	$(ROOTXPG4PROG)
	$(RM) $@
	$(LN) $(ROOTXPG4PROG) $@

clean:
	$(RM) $(OBJS) $(XPG4OBJS)

lint:	lint_SRCS

include ../Makefile.targ
