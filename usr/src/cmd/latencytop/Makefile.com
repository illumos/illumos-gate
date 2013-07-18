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
# Copyright (c) 2008-2009, Intel Corporation.
# All Rights Reserved.
#

PROG = latencytop
OBJS = latencytop.o display.o dwrapper.o klog.o stat.o table.o util.o
SRCS = $(OBJS:%.o=../common/%.c)

include ../../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)

CERRWARN += -_gcc=-Wno-uninitialized

CPPFLAGS += -DEMBED_CONFIGS -I$(ADJUNCT_PROTO)/usr/include/glib-2.0 \
	-I$(ADJUNCT_PROTO)/usr/lib/glib-2.0/include
C99MODE = $(C99_ENABLE)
LDLIBS += -lcurses -ldtrace
all install	:= LDLIBS += -lglib-2.0

LINTFLAGS += -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTFLAGS64 += -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS64 += -erroff=E_FUNC_RET_ALWAYS_IGNOR2

FILEMODE = 0555

ELFWRAP = elfwrap
WRAPOBJ = latencytop_wrap.o

CLEANFILES += $(OBJS) $(WRAPOBJ) ./latencytop_d ./latencytop_trans

.KEEP_STATE:

all: $(PROG)

install:        $(SUBDIRS)
	-$(RM) $(ROOTPROG)
	-$(LN) $(ISAEXEC) $(ROOTPROG)

$(PROG): $(OBJS) $(WRAPOBJ)
	$(LINK.c) -o $@ $(OBJS) $(WRAPOBJ) $(LDLIBS)
	$(POST_PROCESS)

$(WRAPOBJ): latencytop_d latencytop_trans
	$(ELFWRAP) $(WRAPOPT) -o $(WRAPOBJ) latencytop_d latencytop_trans

latencytop_d:
	cp ../common/latencytop.d ./latencytop_d

latencytop_trans:
	cp ../common/latencytop.trans ./latencytop_trans

clean:
	$(RM) $(CLEANFILES)

lint:	lint_SRCS

%.o: ../common/%.c
	$(COMPILE.c) $<

include ../../Makefile.targ
