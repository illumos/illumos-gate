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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

COMMONOBJS=	plugin_common.o
OBJECTS=	$(PLUG_OBJS) $(COMMONOBJS)

include $(SRC)/lib/Makefile.lib

CPPFLAGS +=	-I$(SRC)/lib/libsasl/include

CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

LIBS =		$(DYNLIB)
SRCS=		$(PLUG_OBJS:%.o=../%.c) \
		$(COMMONOBJS:%.o=$(SRC)/lib/libsasl/plugin/%.c)
LDLIBS +=	-lsocket -lc $(PLUG_LIBS)

MAPFILES =	../../mapfile-vers

ROOTLIBDIR=	$(ROOT)/usr/lib/sasl
ROOTLIBDIR64=	$(ROOT)/usr/lib/sasl/$(MACH64)


CFLAGS +=	$(CCVERBOSE) $(XSTRCONST) $(ENC_FLAGS)
CFLAGS64 +=	$(XSTRCONST) $(ENC_FLAGS)

.KEEP_STATE:

all:	$(LIBS)


pics/%.o: $(SRC)/lib/libsasl/plugin/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
