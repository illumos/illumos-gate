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
# Copyright (c) 2019, Joyent, Inc.
#

FSTYPE=		ufs
LIBPROG=	mkfs
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype
include		../Makefile.roll

CPPFLAGS +=	-I../../

OBJS=		$(LIBPROG).o $(ROLLOBJS) $(FSLIB)
SRCS=		$(LIBPROG).c $(ROLLSRCS) $(FSLIBSRC)
MKFSOBJS=	mkfs.o

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-empty-body
CERRWARN +=	$(CNOWARN_UNINIT)

# can't hack main() !
SMATCH =	off

# for messaging catalog
#
POFILE= mkfs.po

catalog:	$(POFILE)

$(POFILE):      $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)   > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	sed "/^domain/d" messages.po >  $@
	$(RM) $(POFILE).i messages.po

CPPFLAGS +=	-D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
LDLIBS +=	-ladm -lefi

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

lint:		lint_SRCS

clean:
	$(RM) $(MKFSOBJS)

