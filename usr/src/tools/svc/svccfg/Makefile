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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2020 Joyent, Inc.
#

include $(SRC)/tools/Makefile.tools
include $(SRC)/cmd/svc/svccfg/Makefile.shared.com

SRCDIR = $(SRC)/cmd/svc/svccfg
COMDIR = $(SRC)/cmd/svc/common

CPPFLAGS +=	-I. -I$(SRC)/cmd/svc/svccfg -I$(SRC)/cmd/svc/common	\
		-I$(NATIVE_ADJUNCT)/include/libxml2			\
		-DNATIVE_BUILD						\
		-I$(LIBSCF)/inc						\
		-I$(LIBTECLA)						\
		-I$(LIBUUTIL)/common

LIBTECLA	= $(SRC)/lib/libtecla		# just for the header
LIBUUTIL	= $(SRC)/lib/libuutil

SVCCFG_EXTRA_LIBS += -lxml2 -lscf -ll -luutil -lumem -lmd \
	-lnvpair
NATIVE_LIBS += libxml2.so libl.so libumem.so libmd.so libnvpair.so libc.so

LDLIBS += \
	-L$(SRC)/tools/svc/libscf -R '$$ORIGIN/../../lib/$(MACH)' \
	-L$(NATIVE_ADJUNCT)/lib -R$(NATIVE_ADJUNCT)/lib -L$(ROOTONBLDLIBMACH) \
	$(SVCCFG_EXTRA_LIBS)

include $(SRC)/Makefile.native

.KEEP_STATE:
.PARALLEL: $(OBJS)

all debug: $(PROG)

$(PROG): $(OBJS) $(MAPFILES)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTONBLDMACHPROG)

clean:
	$(RM) $(OBJS)

include ../../Makefile.targ
include $(SRC)/cmd/svc/svccfg/Makefile.shared.targ
