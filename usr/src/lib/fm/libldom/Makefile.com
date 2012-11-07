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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY = libldom.a
VERS = .1

LIBSRCS = ldom.c ldom_alloc.c ldmsvcs_utils.c ldom_xmpp_client.c ldom_utils.c
OBJECTS = $(LIBSRCS:%.c=%.o)

include ../../../Makefile.lib
include ../../Makefile.lib

SRCS = $(LIBSRCS:%.c=../sparc/%.c)
SRCDIR = ../sparc

LIBS = $(DYNLIB) $(LINTLIB)

CPPFLAGS += -I. -I$(SRC)/uts/sun4v -I$(ROOT)/usr/platform/sun4v/include \
	-I$(ADJUNCT_PROTO)/usr/include/libxml2
CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CFLAGS64 += $(CCVERBOSE) $(C_BIGPICFLAGS)

CERRWARN += -_gcc=-Wno-parentheses

$(DYNLIB) := LDLIBS += $(MACH_LDLIBS)
$(DYNLIB) := LDLIBS += -lfmd_agent -lnvpair -lscf -lmdesc -lc -lxml2 -lsocket \
	-lumem

LINTFLAGS = -msux
LINTFLAGS64 = -msux -m64

$(LINTLIB) := SRCS = $(SRCDIR)/$(LINTSRC)
$(LINTLIB) := LINTFLAGS = -nsvx -I$(ROOT)/usr/platform/sun4v/include
$(LINTLIB) := LINTFLAGS64 = -nsvx -m64 \
	-I$(ROOT)/usr/platform/sun4v/include

.KEEP_STATE:

all: $(LIBS)

lint: $(LINTLIB) lintcheck

pics/%.o: ../$(MACH)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../../Makefile.targ
include ../../Makefile.targ
