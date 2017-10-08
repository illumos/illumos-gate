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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		mv
XPG4PROG=	mv
OBJS1=		mv.o
OBJS=           $(OBJS1) getresponse.o
CPFILE=		cp
LNFILE=		ln
XPG4OBJS=	$(OBJS:%.o=xpg4_%.o)
SRCS=		$(OBJS1:%.o=%.c) $(SRC)/common/util/getresponse.c

ROOTLINKS= $(ROOTBIN)/$(CPFILE) $(ROOTBIN)/$(LNFILE)
ROOTXPG4LINKS= $(ROOTXPG4BIN)/$(CPFILE) $(ROOTXPG4BIN)/$(LNFILE)

include ../Makefile.cmd

clean $(XPG4)	:= OBJS += values-xpg4.o

CLOBBERFILES += $(CPFILE) $(LNFILE)
CFLAGS	+=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized
$(XPG4) := CFLAGS += -DXPG4
LINTFLAGS += -DXPG4 -u
XGETFLAGS += -a -x mv.xcl
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -I $(SRC)/common/util

lint :=	LDLIBS += -lcmdutils -lavl -lsec -lnvpair
$(PROG) := LDLIBS += -lcmdutils -lavl -lsec -lnvpair
$(XPG4) := LDLIBS += -lcmdutils -lavl -lsec -lnvpair

.KEEP_STATE:

all:	$(PROG) $(CPFILE) $(LNFILE) $(XPG4)

$(PROG):	$$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(XPG4):	$$(XPG4OBJS)
	$(LINK.c) -o $@ $(XPG4OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o:    $(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

xpg4_%.o:    %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

xpg4_%.o:    $(SRC)/common/util/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%values-xpg4.o:		../../lib/crt/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/crt/common/values-xpg4.c

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
