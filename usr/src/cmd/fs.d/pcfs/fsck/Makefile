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

FSTYPE=		pcfs
LIBPROG=	fsck
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

FSCKOBJS=	fsck.o bpb.o clusters.o fat.o dir.o pcfs_common.o
FSCKSRCS=	$(FSCKOBJS:%.o=%.c)

#
#  Error injection module for debugging purposes
#
#DEBUGOBJS=	inject.o
#DEBUGSRCS=	$(DEBUGOBJS:%.o=%.c)

OBJS=		$(FSCKOBJS) $(DEBUGOBJS)
SRCS=		$(FSCKSRCS) $(DEBUGSRCS)
LSRCS=		$(FSCKSRCS) $(DEBUGSRCS)

# for messaging catalog
#
POFILE= fsck.po

catalog:        $(POFILE)

CPPFLAGS +=	-D_LARGEFILE64_SOURCE

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	$(CNOWARN_UNINIT)

#
# We need to tell lint not to complain about the routines
# we are grabbing from the kernel as being undefined.
#
LINTFLAGS += -u

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

lint_LSRCS:
	$(LINT.c) $(LSRCS) $(LDLIBS)

lint:	lint_LSRCS

clean:
	$(RM) $(FSCKOBJS) $(DEBUGOBJS)
