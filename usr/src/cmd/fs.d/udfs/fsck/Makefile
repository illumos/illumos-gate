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
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		udfs
LIBPROG=	fsck
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

FSCKOBJS=	main.o setup.o utilities.o pass1.o inode.o
FSCKSRCS=	$(FSCKOBJS:%.o=%.c)

UDFSDIR=	../mkfs
UDFSOBJS=	udfslib.o
#UDFSSRCS=	$(UDFSOBJS:%.o=%.c)

CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses

# not linted
SMATCH=off

OBJS=		$(FSCKOBJS) $(UDFSOBJS)
SRCS=		$(FSCKSRCS) $(UDFSSRCS) ../mkfs/udfslib.c

#CPPFLAGS +=	-D_LARGEFILE64_SOURCE
CPPFLAGS +=	-I../mkfs
LDLIBS += -ladm
$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

%.o:	$(UDFSDIR)/%.c
	$(COMPILE.c) $<

# for messaging catalog
#
POFILE= fsck.po

# for messaging catalog
#
catalog:        $(POFILE)

$(POFILE):      $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)   > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	sed "/^domain/d" messages.po >  $@
	$(RM) $(POFILE).i messages.po

lint:
	$(LINT.c) -mu $(SRCS)

clean:     
	$(RM) $(FSCKOBJS) $(UDFSOBJS)

putback:
	-cstyle -p inode.c
	-cstyle -p main.c
	-cstyle -p pass1.c
	-cstyle -p setup.c
	-cstyle -p utilities.c
	-keywords inode.c
	-keywords main.c
	-keywords pass1.c
	-keywords setup.c
	-keywords utilities.c
	-keywords Makefile
