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
# Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG= tar
DEFAULTFILES= tar.dfl
OBJS1=		tar.o
OBJS=		$(OBJS1) getresponse.o
SRCS=		$(OBJS1:%.o=%.c) $(SRC)/common/util/getresponse.c

include ../Makefile.cmd

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -I $(SRC)/common/util
DCFILE= $(PROG).dc

LINTFLAGS += -u
LDLIBS += -lsec -lcmdutils -lnvpair -ltsol

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-uninitialized

CPPFLAGS += -DEUC

ROOTSYMLINK=	$(ROOTPROG)

XGETFLAGS += -a -x tar.xcl

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG) $(ROOTETCDEFAULTFILES) $(ROOTSYMLINK)
	-$(RM) -r $(ROOTETCPROG)
	-$(SYMLINK) ../usr/sbin/$(PROG) $(ROOTETCPROG)

$(ROOTSYMLINK):
	$(RM) $@; $(SYMLINK) ../sbin/$(PROG) $@

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

clean:
	$(RM) $(OBJS)   

lint:	lint_SRCS

$(DCFILE):
	$(RM) messages.po
	$(XGETTEXT) -c TRANSLATION_NOTE -t $(PROG).c
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

include ../Makefile.targ
