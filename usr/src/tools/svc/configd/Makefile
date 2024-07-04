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
# Copyright 2015 RackTop Systems.
# Copyright 2020 Joyent, Inc.
#

include $(SRC)/tools/Makefile.tools
include $(SRC)/cmd/svc/configd/Makefile.shared.com


LIBUUTIL	= $(SRC)/lib/libuutil
LIBSCF		= $(SRC)/lib/libscf
LIBSQLITE	= $(SRC)/lib/libsqlite

CPPFLAGS += -I$(SRC)/cmd/svc/configd \
	-I$(SRC)/cmd/svc/common -I$(SRC)/common/svc \
	-D_REENTRANT -I$(LIBUUTIL)/common -I$(LIBSCF)/inc -I$(LIBSQLITE) \
	-I$(SRC)/tools/svc/libsqlite \

CPPFLAGS += -DNATIVE_BUILD

LDFLAGS += $(BDIRECT)
LDLIBS	+= -L$(NATIVE_ADJUNCT)/lib -R$(NATIVE_ADJUNCT)/lib \
	-lumem -L$(ROOTONBLDLIBMACH) \
	-R '$$ORIGIN/../../lib/$(MACH)' -lsqlite-sys -luutil

NATIVE_LIBS += libumem.so libc.so

include $(SRC)/Makefile.native

.KEEP_STATE:
.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: $(SRC)/cmd/svc/configd/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

install: all $(ROOTONBLDMACHPROG)

clean:

clobber: clean

include $(SRC)/cmd/Makefile.targ
