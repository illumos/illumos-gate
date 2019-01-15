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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libtecla.a
VERS=		.1
OBJECTS=	getline.o keytab.o freelist.o strngmem.o hash.o history.o \
	direader.o homedir.o pathutil.o expand.o stringrp.o cplfile.o \
	cplmatch.o pcache.o version.o chrqueue.o ioutil.o errmsg.o

include ../../Makefile.lib

SRCDIR =	../common
LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc
$(DYNLIB) :=	LDLIBS += -lcurses
CPPFLAGS +=	-I$(SRCDIR) -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 \
	-DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 \
	-DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 \
	-DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DUSE_TERMINFO=1 -DHAVE_CURSES_H=1 \
	-DHAVE_TERM_H=1 -DHAVE_SYS_SELECT_H=1 -DHAVE_SELECT=1 \
	-DHAVE_SYSV_PTY=1 -D__EXTENSIONS__=1 -D_POSIX_C_SOURCE=199506L \
	-DPREFER_REENTRANT
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

CERRWARN +=	-_gcc=-Wno-type-limits

# not linted
SMATCH=off

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include ../../Makefile.targ
