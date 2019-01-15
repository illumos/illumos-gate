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

LIBRARY=	libinstzones.a
VERS=		.1

OBJECTS =	\
	    	zones_args.o \
		zones_exec.o \
		zones_locks.o \
		zones_paths.o \
		zones_states.o \
		zones_str.o \
		zones_utils.o \
		zones_lofs.o \
		zones.o

# include library definitions
include $(SRC)/lib/Makefile.lib

SRCDIR=		../common

POFILE =	libinstzones.po
MSGFILES =	$(OBJECTS:%.o=../common/%.i)
CLEANFILES +=	$(MSGFILES)

# openssl forces us to ignore dubious pointer casts, thanks to its clever
# use of macros for stack management.
LINTFLAGS=	-umx -errtags \
		-erroff=E_BAD_PTR_CAST_ALIGN,E_BAD_PTR_CAST
$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-address

# not linted
SMATCH=off

LIBS = $(DYNLIB) $(LINTLIB)

DYNFLAGS += $(ZLAZYLOAD)

LDLIBS +=	-lc -lcontract -lzonecfg

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)

.KEEP_STATE:

all:	$(LIBS)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

lint:	lintcheck

# include library targets
include $(SRC)/lib/Makefile.targ
include $(SRC)/Makefile.msg.targ
