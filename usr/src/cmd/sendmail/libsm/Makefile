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

include		../../Makefile.cmd
include		../Makefile.cmd

INCPATH=	-I. -I../src -I../include
CPPFLAGS=	$(INCPATH) $(DBMDEF) $(CPPFLAGS.sm)

ARFLAGS=	cq

OBJS=   assert.o cf.o clock.o clrerr.o config.o debug.o errstring.o exc.o \
	fclose.o feof.o ferror.o fflush.o fget.o findfp.o flags.o fopen.o \
	fpos.o fprintf.o fpurge.o fput.o fread.o fscanf.o fseek.o fvwrite.o \
	fwalk.o fwrite.o get.o heap.o ldap.o makebuf.o match.o mbdb.o \
	memstat.o niprop.o path.o put.o refill.o rewind.o rpool.o setvbuf.o \
	sem.o shm.o signal.o smstdio.o snprintf.o sscanf.o stdio.o \
	strcasecmp.o strdup.o strerror.o strexit.o string.o stringf.o strio.o \
	strl.o strrevcmp.o strto.o test.o ungetc.o util.o vasprintf.o \
	vfprintf.o vfscanf.o vprintf.o vsnprintf.o wbuf.o wsetup.o xtrap.o

SRCS=	$(OBJS:%.o=%.c)

TESTS=	t-event t-exc t-rpool t-string t-smstdio t-match t-strio t-heap \
	t-fopen t-strl t-strrevcmp t-path t-float t-scanf t-sem t-shm \
	t-memstat t-qic

libsm=	libsm.a

CERRWARN +=	-_gcc=-Wno-type-limits

.KEEP_STATE:
all: $(libsm)

.PARALLEL:	$(OBJS)

$(libsm): $(OBJS)
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean:
	$(RM) $(OBJS) $(libsm) $(TESTS) foo t-smstdio.1

depend obj:

install: all

LDLIBS += -lldap

lint:	lint_SRCS

test: $(TESTS)

t-%:	t-%.c
	$(LINK.c) $< -o $@ $(libsm) $(LDLIBS)
	$(POST_PROCESS)
	./$@

include		../../Makefile.targ
