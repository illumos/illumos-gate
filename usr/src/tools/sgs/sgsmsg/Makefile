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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Makefile to support tools used for linker development:
#
#  o	sgsmsg creates message headers/arrays/catalogs (a native tool).
#
# Note, these tools are not part of the product.
#

include		../Makefile.com
include		../../Makefile.tools
include		$(SRC)/cmd/Makefile.cmd


PROG=	sgsmsg

MAN1ONBLDFILES =	sgsmsg.1onbld
$(ROOTONBLDMAN1ONBLDFILES) := FILEMODE=	644

OBJS=	assfail.o \
	avl.o \
	findprime.o \
	sgsmsg.o \
	string_table.o

FILEMODE=	0755

CPPFLAGS =	$(NATIVE_CPPFLAGS)
CFLAGS =	$(NATIVE_CFLAGS)
CW_LINKER =

# not linted
SMATCH=		off

all: $(PROG)

install: $(ROOTONBLDMACHPROG) $(ROOTONBLDMAN1ONBLDFILES)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)

%.o:	$(SGSCOMMON)/%.c
	$(NATIVECC) $(DEBUG) $(NATIVE_CFLAGS) $(CPPFLAGS) -c $<

avl.o:	$(SRC)/common/avl/avl.c
	$(NATIVECC) $(DEBUG) $(NATIVE_CFLAGS) $(CPPFLAGS) -c \
	    $(SRC)/common/avl/avl.c

clean:
	$(RM) $(OBJS)

include $(SRC)/cmd/Makefile.targ
