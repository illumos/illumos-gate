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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG=		nfsref

POFILE=		nfsref.po

include		../../../Makefile.cmd

CFLAGS +=	$(CCVERBOSE) -I../lib
OBJS=	nfsref.o ref_subr.o
SRCS=	nfsref.c

CSTD= $(CSTD_GNU99)

CERRWARN += -_gcc=-Wno-unused-variable

# not linted
SMATCH=off

LDLIBS += -lreparse -lnvpair -lnsl -lumem

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(LDLIBS) $(OBJS)
		$(POST_PROCESS)

FILEMODE=       0555

.KEEP_STATE:

all:		$(PROG)

ref_subr.o:	../lib/ref_subr.c
	$(COMPILE.c) ../lib/ref_subr.c

install:	all $(ROOTUSRSBINPROG)

catalog: $(POFILE)

$(POFILE): $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)   > $(POFILE).i
	$(XGETTEXT)     $(XGETFLAGS) $(POFILE).i
	sed "/^domain/d"        messages.po     > $@
	$(RM) $(POFILE).i messages.po

clean:
	$(RM) $(OBJS)

include ../../../Makefile.targ
