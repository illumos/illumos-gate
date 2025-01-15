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
# Copyright (c) 1998 by Sun Microsystems, Inc.
# All rights reserved.
# Copyright 2024 MNX Cloud, Inc.
#

FSTYPE=		pcfs
LIBPROG=	mkfs
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

OBJS=		mkfs_main.o pcfs_common.o getresponse.o
SRCS=		mkfs_main.c ../common/pcfs_common.c
SRCS +=		$(SRC)/common/util/getresponse.c
LDLIBS +=	-lefi

# for messaging catalog
#
POFILE= mkfs.po

catalog:        $(POFILE)

CPPFLAGS +=	-D_LARGEFILE64_SOURCE
CPPFLAGS +=	-I../common
CPPFLAGS +=	-I$(SRC)/common/util
CPPFLAGS +=	-I$(SRC)/uts/common
CPPFLAGS +=	-I$(SRC)/cmd/boot/installboot/i386
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

$(LIBPROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS) $(POFILE).i messages.po

$(POFILE):
	$(RM) $@
	$(COMPILE.cpp) $(SRCS) > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS) $(POFILE).i
	sed "/^domain/d" messages.po > $@
	$(RM) $(POFILE).i messages.po

%.o : ../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

%.o : $(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)
