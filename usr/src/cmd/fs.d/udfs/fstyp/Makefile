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

FSTYP_VERS=1
FSTYPE=		udfs
LIBPROG=	fstyp.so.${FSTYP_VERS} 

include ../../../../lib/Makefile.lib
include ../../Makefile.fstype

# There should be a mapfile here
MAPFILES =

CFLAGS +=	$(C_PICFLAGS)
DYNLIB=		$(LIBPROG)

CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-uninitialized

LDLIBS += -lnvpair -ladm -lc

LINTFLAGS += -erroff=E_STATIC_UNUSED -erroff=E_NAME_DEF_NOT_USED2
LINTFLAGS64 += -erroff=E_STATIC_UNUSED -erroff=E_NAME_DEF_NOT_USED2

#
# Override PMAP dependency
#
PMAP=

# No msg catalog here.
POFILE=

OBJS= fstyp.o ud_lib.o

SRCS= $(OBJS:%.o=%.c)

CPPFLAGS += 	-DFSTYP_VERS=${FSTYP_VERS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

$(LIBPROG): $(OBJS)
	$(LINK.c) $(CPPFLAGS) $(CFLAGS) $(DYNFLAGS) $(GSHARED) -o $@ $(OBJS) \
	    $(LDLIBS)
	$(POST_PROCESS_SO)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

.KEEP_STATE:

all: $(LIBPROG)

install: all
	$(RM) $(ROOTLIBFSTYPE)/fstyp
	$(LN) $(ROOTUSRSBIN)/fstyp $(ROOTLIBFSTYPE)/fstyp

lint: lint_SRCS

cstyle:
	$(CSTYLE) $(SRCS)

clean:     
	$(RM) $(OBJS)
