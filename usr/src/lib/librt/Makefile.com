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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/librt/Makefile.com

LIBRARY=	librt.a
VERS=		.1

OBJECTS=	\
	aio.o		\
	clock_timer.o	\
	fallocate.o	\
	fdatasync.o	\
	mqueue.o	\
	pos4.o		\
	pos4obj.o	\
	sched.o		\
	sem.o		\
	shm.o		\
	sigrt.o

include ../../Makefile.lib
include ../../Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS += 	-laio -lmd5 -lc
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR=		../common
MAPDIR=		../spec/$(TRANSMACH)
SPECMAPFILE=	$(MAPDIR)/mapfile

ROOTLINTDIR64=	$(ROOTLIBDIR64)
ROOTLINKS64=    $(ROOTLIBDIR64)/$(LIBLINKS)

CFLAGS	+=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../../common/inc

#
# If and when somebody gets around to messaging this, CLOBBERFILE should not
# be cleared (so that any .po file will be clobbered.
#
CLOBBERFILES=	test

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

# install rule for 64 bit lint library target
$(ROOTLINTDIR64)/%.ln:	%.ln
	$(INS.file)
	cd $(ROOTLINTDIR64); \
		$(RM) llib-lposix4.ln ; \
		$(SYMLINK) ./llib-lrt.ln llib-lposix4.ln ;

# install rule for lint library target
$(ROOTLINTDIR)/%.ln:	%.ln
	$(INS.file)
	cd $(ROOTLINTDIR); \
		$(RM) llib-lposix4 ; \
		$(SYMLINK) ./llib-lrt llib-lposix4 ; \
		$(RM) llib-lposix4.ln ; \
		$(SYMLINK) ./llib-lrt.ln llib-lposix4.ln ;

include ../../Makefile.targ

# install rules for 32-bit librt.so in /usr/lib
$(ROOTLINKS) := INS.liblink= \
	$(RM) $@; $(SYMLINK) $(LIBLINKPATH)$(LIBLINKS)$(VERS) $@; \
		cd $(ROOTLIBDIR); \
		$(RM)  libposix4.so$(VERS) libposix4.so; \
		$(SYMLINK) librt.so$(VERS) libposix4.so$(VERS); \
		$(SYMLINK) libposix4.so$(VERS) libposix4.so;

# install rules for 64-bit librt.so in /usr/lib/sparcv9
$(ROOTLIBDIR64)/$(LIBLINKS) := INS.liblink64 = \
	-$(RM) $@; \
	cd $(ROOTLIBDIR64); \
	$(RM) libposix4.so$(VERS) libposix4.so ; \
	$(SYMLINK) $(LIBLINKS)$(VERS) $(LIBLINKS); \
	$(SYMLINK) librt.so$(VERS) libposix4.so$(VERS); \
	$(SYMLINK) libposix4.so$(VERS) libposix4.so

