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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		ufs
LIBPROG=	fssnap

include		../../Makefile.fstype
FSSNAPOBJS=	fssnap.o
FSSNAPSRCS=	$(FSSNAPOBJS:%.o=%.c)

TOPDIR=		../..
TOPOBJS=	fssnapsup.o
TOPSRCS=	$(TOPOBJS:%.o=%.c)

OBJS=		$(FSSNAPOBJS) $(TOPOBJS)
SRCS=		$(FSSNAPSRCS) $(TOPSRCS)

CPPFLAGS +=     -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

LDLIBS +=	-lkstat -ldevinfo

# message catalog
POFILE= fssnap.po

catalog:	$(POFILE)

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

%.o:	$(TOPDIR)/%.c
	$(COMPILE.c) $<


lint:	lint_SRCS

clean:     
	$(RM) $(FSSNAPOBJS) $(TOPOBJS)
