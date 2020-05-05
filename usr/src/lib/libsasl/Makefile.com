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

LIBRARY= libsasl.a
VERS= .1

SASLOBJS=	auxprop.o	canonusr.o	checkpw.o	client.o \
		common.o	config.o	dlopen.o	external.o \
		md5.o		saslutil.o	seterror.o	server.o

COMMONOBJS=	plugin_common.o

OBJECTS=	$(SASLOBJS) $(COMMONOBJS)

include ../../Makefile.lib

LIBS=		$(DYNLIB)
SRCS=		$(SASLOBJS:%.o=../lib/%.c) $(COMMONOBJS:%.o=$(PLUGDIR)/%.c)
LDLIBS +=	-lsocket -lc -lmd

SRCDIR=		../lib
PLUGDIR=	../plugin

CFLAGS +=	$(CCVERBOSE) $(XSTRCONST)
CFLAGS64 +=	$(XSTRCONST)
CPPFLAGS +=	-I../include -I$(PLUGDIR)

# not linted
SMATCH=off

.KEEP_STATE:

all: $(LIBS)


pics/%.o: $(PLUGDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
