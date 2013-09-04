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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../../../Makefile.cmd

COMMON = ..

PROG=		sharectl

SHARECTL_MOD	= sharectl

SHARECTL_SRC	= $(SHARECTL_MOD:%=$(COMMON)/%.c) shareutil.c

SHARECTL_OBJ	= $(SHARECTL_MOD:%=%.o) shareutil.o


MYCPPFLAGS = 	-I.. -I../../sharemgr
CPPFLAGS += $(MYCPPFLAGS)
LDLIBS += -lshare -lumem

CERRWARN += -_gcc=-Wno-uninitialized

SRCS = $(SHARECTL_SRC)
OBJS = $(SHARECTL_OBJ)
MODS = $(SHARECTL_MOD)

CLOBBERFILES = $(MODS) $(POFILE) $(POFILES) shareutil.c

POFILES = $(SHARECTL_SRC:.c=.po)
POFILE  = sharectl.po

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

install: all $(ROOTUSRSBINPROG)

lint:	$(SHARECTL_MOD).ln $(SHARECTL_SRC:.c=.ln)

clean:
	$(RM) $(OBJS)

%.ln: FRC
	$(LINT.c) $(SHARECTL_SRC) $(LDLIBS)

include ../../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

%.o: $(COMMON)/%.c
	$(COMPILE.c) -o $@ $<

shareutil.c: ../../sharemgr/shareutil.c
	$(CP) -f ../../sharemgr/shareutil.c shareutil.c

FRC:
