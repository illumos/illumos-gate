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


LIBRARY= libdyn.a
VERS= .1

DYNOBJS= \
	dyn_create.o \
        dyn_put.o \
        dyn_debug.o \
        dyn_delete.o \
        dyn_size.o \
        dyn_append.o \
        dyn_realloc.o \
        dyn_paranoid.o \
        dyn_insert.o \
        dyn_initzero.o

OBJECTS= $(DYNOBJS)

# include library definitions
include ../../Makefile.lib

SRCS=	$(DYNOBJS:%.o=../%.c)
LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5


#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=     -D_REENTRANT -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 \
		-DHAVE_UNISTD_H=1 -DHAVE_UMASK=1 -DHAVE_SRAND48=1 \
		-DHAVESRAND=1 -DHAVESRANDOM=1 -DHAVE_RE_COMP=1 \
		-DHAVE_RE_EXEC=1 -DHAVE_REGCOMP=1 -DHAVE_REGEXEC=1 \
		-DHAVE_COMPILE=1

CFLAGS +=	$(CCVERBOSE) -I..
LDLIBS +=	-lc

CERRWARN +=	-_gcc=-Wno-unused-variable

SMOFF += no_if_block

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

# include library targets
include ../../Makefile.targ

FRC:
