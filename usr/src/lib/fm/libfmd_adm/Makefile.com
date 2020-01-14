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

LIBRARY = libfmd_adm.a
VERS = .1

LIBSRCS = fmd_adm.c
OBJECTS = $(LIBSRCS:%.c=%.o) fmd_rpc.o fmd_xdr.o

include ../../../Makefile.lib
include ../../Makefile.lib

SRCS = $(LIBSRCS:%.c=../common/%.c)
LIBS = $(DYNLIB) $(LINTLIB)
CLEANFILES += fmd_rpc.c fmd_xdr.c fmd_rpc_adm.h fmd_rpc_adm.x

SRCDIR =	../common

CPPFLAGS += -I../common -I.
CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CFLAGS64 += $(CCVERBOSE) $(C_BIGPICFLAGS)
CERRWARN += -_gcc=-Wno-unused-variable
LDLIBS += -lnvpair -lnsl -lc

LINTFLAGS = -msux
LINTFLAGS64 = -msux -m64

$(LINTLIB) := SRCS = $(SRCDIR)/$(LINTSRC)
$(LINTLIB) := LINTFLAGS = -nsvx
$(LINTLIB) := LINTFLAGS64 = -nsvx -m64

.KEEP_STATE:

all: $(LIBS)

lint: $(LINTLIB) lintcheck

fmd_rpc_adm.x: $(SRC)/cmd/fm/fmd/common/fmd_rpc_adm.x
	$(RM) $@; $(CP) $? $@

fmd_rpc_adm.h: fmd_rpc_adm.x
	$(RPCGEN) -CMN -h -o $@ fmd_rpc_adm.x

../common/fmd_adm.c: fmd_rpc_adm.h

fmd_rpc.c: fmd_rpc_adm.x
	$(RPCGEN) -CMN -l -o $@ fmd_rpc_adm.x

fmd_xdr.c: fmd_rpc_adm.x
	$(RPCGEN) -CMN -c -o $@ fmd_rpc_adm.x

pics/%.o: ../$(MACH)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../../Makefile.targ
include ../../Makefile.targ
