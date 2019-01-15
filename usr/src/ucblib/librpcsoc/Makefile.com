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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= librpcsoc.a
VERS = .1

CLOBBERFILES += lint.out


OBJECTS= clnt_tcp.o clnt_udp.o getrpcport.o rtime.o svc_tcp.o svc_udp.o get_myaddress.o

# include library definitions
include $(SRC)/lib/Makefile.lib

objs/%.o pics/%.o: ../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

LIBS = $(DYNLIB)

LDLIBS += -lnsl -lsocket -lc
CPPFLAGS += -DPORTMAP
DYNFLAGS += $(ZINTERPOSE)

ROOTLIBDIR=	$(ROOT)/usr/ucblib
ROOTLIBDIR64=   $(ROOT)/usr/ucblib/$(MACH64)

CPPFLAGS = -I$(SRC)/ucbhead -I../../../lib/libc/inc $(CPPFLAGS.master)

CERRWARN += -_gcc=-Wno-uninitialized

# not linted
SMATCH=off

.KEEP_STATE:

lint: lintcheck

# include library targets
include $(SRC)/lib/Makefile.targ
include ../../Makefile.ucbtarg

