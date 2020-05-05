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
# Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2019, Joyent, Inc.

LIBRARY=	libtnfprobe.a
VERS=		.1
OBJECTS.c=	tnf_buf.o	\
		trace_init.o	\
		trace_funcs.o	\
		debug_funcs.o	\
		probe_mem.o	\
		tnf_args.o	\
		tnf_trace.o	\
		probe_cntl.o

UFSDIR=		$(SRC)/uts/common/tnf
UFSOBJS=	tnf_writer.o tnf_probe.o

OBJECTS.s=	$(MACH)_locks.o

OBJECTS=	$(OBJECTS.c) $(UFSOBJS) $(OBJECTS.s)

include ../../Makefile.lib

LIBS=		$(DYNLIB)

DYNFLAGS +=	$(ZINTERPOSE)

HDRS=		com.h writer.h probe.h
ROOTHDRDIR=	$(ROOT)/usr/include/tnf
ROOTHDRS=	$(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=	$(HDRS:%.h=%.check)
$(ROOTHDRS) :=	FILEMODE = 0644
CHECKHDRS =	$(HDRS:%.h=%.check)

# Include .. first to pick up tnf_trace.h in current dir, Include UFSDIR to
#	pick up tnf_types.h
CPPFLAGS +=	-I.. -I$(UFSDIR) -D_REENTRANT -D_TNF_LIBRARY


CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

$(ROOTHDRS) :=	FILEMODE = 644

LDLIBS += -lc

.KEEP_STATE:

all: $(LIBS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS)


check: $(CHECKHDRS)

$(ROOTLIBDIR) $(ROOTHDRDIR):
	$(INS.dir)

$(ROOTHDRDIR)/% : %
	$(INS.file)

#ASFLAGS=	$(AS_PICFLAGS) -P -D_SYS_SYS_S -D_LOCORE -D_ASM -DPIC -DLOCORE $(CPPFLAGS)
ASFLAGS=	-P -D_SYS_SYS_S -D_LOCORE -D_ASM -DPIC -DLOCORE $(CPPFLAGS)
BUILD.s=	$(AS) $(ASFLAGS) $< -o $@

objs/%.o pics/%.o: ../%.s
		$(COMPILE.s) -o $@ $<
		$(POST_PROCESS_S_O)

pics/%.o objs/%.o: ../%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)

pics/%.o objs/%.o:	$(UFSDIR)/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)

include ../../Makefile.targ
