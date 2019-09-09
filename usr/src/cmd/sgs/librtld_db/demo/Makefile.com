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
# Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG=		rdb

# DEMO DELETE START
include		../../../../Makefile.cmd
# DEMO DELETE END

MACH:sh=	uname -p

CFLAGS +=	$(DEMOCFLAGS)

COMSRC=		bpt.c dis.c main.c ps.c gram.c lex.c globals.c help.c \
		utils.c maps.c syms.c callstack.c disasm.c
M_SRC=		regs.c m_utils.c

BLTSRC=		gram.c lex.c
BLTHDR=		gram.h

# DEMO DELETE START
ONLDLIBDIR=	/opt/SUNWonld/lib

# DEMO DELETE END
OBJDIR=		objs
OBJS =		$(COMSRC:%.c=$(OBJDIR)/%.o) $(M_SRC:%.c=$(OBJDIR)/%.o)

SRCS =		$(COMSRC:%=../common/%) $(M_SRC)

MV =		mv

.PARALLEL:	$(OBJS)

CPPFLAGS=	-I../common -I. $(CPPFLAGS.master)
LDLIBS +=	-lrtld_db -lelf -ll -ly

CLEANFILES +=	$(BLTSRC) $(BLTHDR) simp libsub.so.1

# DEMO DELETE START

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-variable
SMOFF +=	buffer_too_small_for_struct
# DEMO DELETE END

test-sparc=	test-sparc-regs
test-i386=
TESTS=		test-maps test-breaks test-steps test-plt_skip \
		    test-object-padding $(test-$(MACH))

# DEMO DELETE START
ROOTONLDBIN=		$(ROOT)/opt/SUNWonld/bin
ROOTONLDBINPROG=	$(PROG:%=$(ROOTONLDBIN)/%)
ROOTONLDBINPROG64=	$(PROG:%=$(ROOTONLDBIN)/$(MACH64)/%)

FILEMODE=	0755
# DEMO DELETE END
