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
# Copyright 2024 MNX Cloud, Inc.
#

FSTYPE=		pcfs
LIBPROG=	fsck
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

COMMONOBJS=	pcfs_common.o getresponse.o
COMMONSRCS=	../common/pcfs_common.c $(SRC)/common/util/getresponse.c
FSCKOBJS=	fsck_main.o bpb.o clusters.o fat.o dir.o
FSCKSRCS=	$(FSCKOBJS:%.o=%.c)

#
#  Error injection module for debugging purposes
#
#DEBUGOBJS=	inject.o
#DEBUGSRCS=	$(DEBUGOBJS:%.o=%.c)

OBJS=		$(FSCKOBJS) $(DEBUGOBJS) $(COMMONOBJS)
SRCS=		$(FSCKSRCS) $(DEBUGSRCS) $(COMMONSRCS)

# for messaging catalog
#
POFILES=	$(OBJS:%.o=%.po)
POFILE=		fsck.po

catalog:        $(POFILE)

CPPFLAGS +=	-D_LARGEFILE64_SOURCE
CPPFLAGS +=	-I../common
CPPFLAGS +=	-I$(SRC)/common/util

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	$(CNOWARN_UNINIT)

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

%.o : ../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

%.o : $(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

$(POFILE):
	$(RM) $@
	$(COMPILE.cpp) $(SRCS) > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS) $(POFILE).i
	sed "/^domain/d" messages.po > $@
	$(RM) $(POFILE).i messages.po

clean:
	$(RM) $(FSCKOBJS) $(DEBUGOBJS) $(COMMONOBJS) $(POFILE).i messages.po
