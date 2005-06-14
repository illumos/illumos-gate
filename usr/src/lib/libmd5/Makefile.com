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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libmd5/Makefile.com
#

LIBRARY= libmd5.a
VERS= .1

OBJECTS= md5.o
COMMON= $(SRC)/common/crypto/md5

include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

LIBS= $(DYNLIB) $(LINTLIB)

# Macros to help build the shared object
MAPFILE= $(MAPDIR)/mapfile
DYNFLAGS += -M$(MAPFILE)
CPPFLAGS += -D__RESTRICT
CFLAGS += $(CCVERBOSE)

DYNFLAGS +=	$(BDIRECT)
LDLIBS +=	-lc

# Macros to help build the lint library
LINTSRC= $(LINTLIB:%.ln=%)
$(LINTLIB) := SRCS= ../$(LINTSRC)
SRCS= $(OBJECTS:%.o=$(COMMON)/%.c)
ROOTLINT= $(LINTSRC:%=$(ROOTLIBDIR)/%)
$(ROOTLIBDIR)/%: ../%
	$(INS.file)

# The md5 code is very careful about data alignment
# but lint doesn't know that, so just shut lint up.
lint := LINTFLAGS += -erroff=E_BAD_PTR_CAST_ALIGN
lint := LINTFLAGS64 += -erroff=E_BAD_PTR_CAST_ALIGN

.KEEP_STATE:

$(DYNLIB): $(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); pwd; $(MAKE) mapfile

lint: lintcheck

include $(SRC)/lib/Makefile.targ

pics/%.o: $(COMMON)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
