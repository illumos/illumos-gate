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

include ../../../Makefile.cmd

COMMON = ..

PROG=		sharemgr

SHAREMGR_MOD	= sharemgr

COMMONSRC	= sharemgr_main.c commands.c shareutil.c

SHAREMGR_SRC	= $(COMMONSRC:%=$(COMMON)/%)

SHAREMGR_OBJ	= $(COMMONSRC:%.c=%.o)

ROOTLINKS = $(ROOTUSRSBIN)/share $(ROOTUSRSBIN)/unshare

MYCPPFLAGS = -I../../../../lib/libfsmgt/common -I/usr/include/libxml2 \
		-I../..
CPPFLAGS += $(MYCPPFLAGS)
LDLIBS += -lshare -lscf -lsecdb -lumem
all install := LDLIBS += -lxml2
LINTFLAGS	+= -u
LINTFLAGS64	+= -u

SRCS = $(SHAREMGR_SRC)
OBJS = $(SHAREMGR_OBJ)
MODS = $(SHAREMGR_MOD)

CLOBBERFILES = $(MODS)

POFILES = $(SHAREMGR_SRC:.c=.po)
POFILE  = sharemgr.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg:=		TARGET= catalog

.KEEP_STATE:

all: $(MODS)

catalog: $(POFILE)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all

$(ROOTLINKS): $(ROOTUSRSBINPROG)
	$(RM) $@
	$(LN) $(ROOTUSRSBINPROG) $@

lint:	$(SHAREMGR_MOD).ln $(SHAREMGR_SRC:.c=.ln)

clean:
	$(RM) $(OBJS)

check:		$(CHKMANIFEST)

%.ln: FRC
	$(LINT.c) $(SHAREMGR_SRC) $(LDLIBS)

include ../../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

%.o: $(COMMON)/%.c
	$(COMPILE.c) -o $@ $<

FRC:
