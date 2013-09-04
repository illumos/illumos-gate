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

LIBRARY= libsec.a
VERS= .1

YFLAGS =	-d -v -b acl
LFLAGS = 	-t
OBJS_SHARED= acl_common.o
GENERATED_SRCS = acl.tab.o acl_lex.o
OBJS_COMMON= aclcheck.o aclmode.o aclsort.o acltext.o aclutils.o
OBJECTS= $(OBJS_COMMON) $(OBJS_SHARED) $(GENERATED_SRCS)
CLEANFILES += acl_lex.c acl.tab.c acl.tab.h
LINTSRCS = $(OBJS_COMMON)

# include library definitions
include ../../Makefile.lib

SRCDIR=		../common

LIBS =		$(DYNLIB) $(LINTLIB)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -I. -I../../../common/acl
LDLIBS += -lc -lavl -lidmap

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-variable

CLOBBERFILES += acl.output

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCS=		$(OBJS_COMMON:%.o=$(SRCDIR)/%.c) \
		 $(OBJS_SHARED:%.o=$(SRC)/common/acl/%.c)

$(LINTLIB):= SRCS=	$(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: ../../../common/acl/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

acl.tab.c acl.tab.h:	$(SRCDIR)/acl.y
	$(YACC) $(YFLAGS) $(SRCDIR)/acl.y

acl_lex.c: $(SRCDIR)/acl_lex.l acl.tab.h
	$(LEX) $(LFLAGS) $(SRCDIR)/acl_lex.l > $@

include ../../Makefile.targ
