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
# Copyright 2015 Gary Mills
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY= libresolv.a
VERS= .1

PICS=   pics/res_comp.o pics/res_debug.o pics/res_init.o \
	pics/res_mkquery.o pics/res_query.o pics/res_send.o \
	pics/res_gethost.o pics/res_sethost.o

pics/%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

OBJECTS= \
res_gethost.o   res_comp.o      res_debug.o     res_init.o    res_mkquery.o  \
res_query.o     res_send.o      res_sethost.o

# include library definitions
include ../Makefile.lib

# install this library in the root filesystem
include ../Makefile.rootfs

SRCDIR =	.

C99MODE=	$(C99_DISABLE)

# We really want to say this:
#	CPPFLAGS += -DDEBUG -DSYSV -D_REENTRANT -I. -I../common/inc
# but some system header files are replaced by local versions
# so we must put -I. ahead of the default include directories:
CPPFLAGS = -I. -I../common/inc $(CPPFLAGS.master) -DDEBUG -DSYSV -D_REENTRANT
LDLIBS += -lsocket -lnsl -lc
CFLAGS += $(CCVERBOSE)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

ROOTDYNLIBS=	$(DYNLIB:%=$(ROOTLIBDIR)/%)

.KEEP_STATE:

LIBS = $(DYNLIB)

all: $(LIBS)

install: all $(ROOTDYNLIBS)

lint: lintcheck

# include library targets
include ../Makefile.targ
