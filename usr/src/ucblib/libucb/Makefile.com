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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libucb.a
VERS=		.1

PORTSYSOBJS=		\
	flock.o		\
	getdtblsize.o	\
	gethostid.o	\
	gethostname.o	\
	getpagesize.o	\
	gettimeofday.o	\
	killpg.o	\
	mctl.o		\
	reboot.o	\
	setpgrp.o	\
	wait3.o		\
	wait4.o

PORTSTDIOOBJS=		\
	doprnt.o	\
	fopen.o		\
	fprintf.o	\
	printf.o	\
	sprintf.o	\
	vfprintf.o	\
	vprintf.o	\
	vsprintf.o

PORTGENOBJS=		\
	_psignal.o	\
	bcmp.o		\
	bcopy.o		\
	bzero.o		\
	ftime.o		\
	getwd.o		\
	index.o		\
	nice.o		\
	nlist.o		\
	psignal.o	\
	rand.o		\
	readdir.o	\
	regex.o		\
	rindex.o	\
	scandir.o	\
	setbuffer.o	\
	siglist.o	\
	statfs.o	\
	times.o

OBJECTS= $(SYSOBJS) $(PORTGENOBJS) $(PORTSYSOBJS) $(PORTSTDIOOBJS)

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOTLIBDIR=	$(ROOT)/usr/ucblib
ROOTLIBDIR64=	$(ROOT)/usr/ucblib/$(MACH64)

MAPFILES =	../port/mapfile-vers

SRCS=		$(PORTGENOBJS:%.o=../port/gen/%.c) \
		$(PORTSTDIOOBJS:%.o=../port/stdio/%.c) \
		$(PORTSYSOBJS:%.o=../port/sys/%.c)

LIBS = $(DYNLIB)

CFLAGS	+=	$(CCVERBOSE)
CFLAGS64 +=	$(CCVERBOSE)
LDLIBS +=	-lelf -lc

CPPFLAGS = -D$(MACH) -I$(SRC)/ucbhead -I../inc \
		-I../../../lib/libc/inc $(CPPFLAGS.master)

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

ASFLAGS= -P -D__STDC__ -DLOCORE -D_SYS_SYS_S -D_ASM $(CPPFLAGS)

pics/%.o:= ASFLAGS += $(AS_PICFLAGS)

# libc method of building an archive, using AT&T ordering
BUILD.AR= $(RM) $@ ; \
	$(AR) q $@ `$(LORDER) $(OBJECTS:%=$(DIR)/%)| $(TSORT)`

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: ../port/gen/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
pics/%.o: ../port/stdio/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
pics/%.o: ../port/sys/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# shared (sparc/sparcv9/i386/amd64) platform-specific rule
pics/%.o: sys/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../$(MACH)/sys/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

#
# Include library targets
#
include $(SRC)/lib/Makefile.targ
