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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libtnfctl.a
VERS=		.1
OBJECTS.c=	open.o		\
		prb_child.o	\
		prb_shmem.o	\
		prb_proc.o	\
		prb_lmap.o	\
		prb_rtld.o	\
		prb_findexec.o	\
		prb_status.o	\
		util.o		\
		traverse.o	\
		sym.o		\
		elf.o		\
		continue.o	\
		checklib.o	\
		probes.o	\
		probes_ext.o	\
		close.o		\
		targmem.o	\
		comb.o		\
		kernel_int.o	\
		kernel.o	\
		internal.o	\
		status.o


OBJECTS.s=	$(MACH)_assm.o

OBJECTS=	$(OBJECTS.c) $(OBJECTS.s)

include ../../Makefile.lib

# We omit $(OBJECTS.s:%.o=%.s) in the next line, because lint no like
SRCS= $(OBJECTS.c:%.o=../%.c)

LIBS=		$(DYNLIB)

HDRS=		tnfctl.h
ROOTHDRDIR=	$(ROOT)/usr/include/tnf
ROOTHDRS=	$(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=	$(HDRS:%.h=%.check)
$(ROOTHDRS) := 	FILEMODE = 0644
CHECKHDRS =	$(HDRS:%.h=%.check)

LDLIBS +=	-lc -lelf

# Uncomment the following line for a debug build
# COPTFLAG =	-g -DDEBUG $(CCVERBOSE)
CPPFLAGS +=	-I$(SRC)/lib/libtnfprobe -D_REENTRANT -I$(SRC)/cmd/sgs/include

LINTFLAGS +=	-y

CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-empty-body
CERRWARN +=	-_gcc=-Wno-parentheses

ASFLAGS +=	-P

$(ROOTHDRS) :=	FILEMODE = 644

.KEEP_STATE:

all: $(LIBS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS)

lint:
	$(LINT.c) $(SRCS)

check: $(CHECKHDRS)

$(ROOTLIBDIR) $(ROOTHDRDIR):
	$(INS.dir)

$(ROOTHDRDIR)/% : %
	$(INS.file)

BUILD.s=	$(AS) $< -o $@

objs/%.o pics/%.o: ../%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)


%.o:		../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
