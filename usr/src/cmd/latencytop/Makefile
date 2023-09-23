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
# Copyright (c) 2008-2009, Intel Corporation.
# All Rights Reserved.
#
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.

PROG = latencytop
OBJS = latencytop.o display.o dwrapper.o klog.o stat.o table.o util.o

include ../Makefile.cmd
include ../Makefile.cmd.64

CFLAGS += $(CCVERBOSE)

CERRWARN += $(CNOWARN_UNINIT)

# smatch has problems parsing the glib header files
SMATCH=off

CPPFLAGS += -DEMBED_CONFIGS -I$(ADJUNCT_PROTO)/usr/include/glib-2.0 \
	-I$(ADJUNCT_PROTO)/usr/lib/glib-2.0/include
CSTD = $(CSTD_GNU99)
LDLIBS += -lcurses -ldtrace
NATIVE_LIBS += libglib-2.0.so
all install	:= LDLIBS += -lglib-2.0

FILEMODE = 0555

WRAPOBJ = latencytop_wrap.o

CLEANFILES += $(OBJS) $(WRAPOBJ) ./latencytop_d ./latencytop_trans

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

$(PROG): $(OBJS) $(WRAPOBJ)
	$(LINK.c) -o $@ $(OBJS) $(WRAPOBJ) $(LDLIBS)
	$(POST_PROCESS)

latencytop_d: latencytop.d
	$(CP) $^ $@

latencytop_trans: latencytop.trans
	$(CP) $^ $@

$(WRAPOBJ): latencytop_d latencytop_trans
	$(ELFWRAP) -64 -o $(WRAPOBJ) latencytop_d \
		latencytop_trans

clean:
	$(RM) $(CLEANFILES)

include ../Makefile.targ
