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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

ARCH =		$(TARGET_ARCH:-%=%)

PROG =		tbeadm


OBJS =		tbeadm.o
SRCS =		$(OBJS:%.o=../%.c)

include ../../Makefile.lib

#LIBS= 		$(DYNLIB)

INCLUDE =	-I../common

STATICDEPLIBS	= ../$(ARCH)/libbe.a
STATICLDLIBS	+= -linstzones -L/lib -L../$(ARCH) -lzfs -lnvpair \
		-luuid -lgen -Bstatic -lbe -Bdynamic

DEPLIBS		= ../$(ARCH)/libbe.so.1
LDLIBS +=	-L/lib -L../pics/$(ARCH) -lzfs -lnvpair -lbe

CPPFLAGS +=	-D_LARGEFILE64_SOURCE=1 -D_REENTRANT ${INCLUDE}
CFLAGS +=	-g -DDEBUG


$(PROG):	$(OBJS) $(STATICDEPLIBS)
		$(LINK.c) -o $@ $@.c $(OBJS) $(STATICLDLIBS)
		$(POST_PROCESS)

all:		$(PROG)

install_h:

install:	all

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

clobber: clean
	$(RM) tbeadm.o

clean:
	$(RM) tbeadm 

