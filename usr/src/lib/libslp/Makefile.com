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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libslp.a
VERS =		.1

OBJECTS =	SLPFindAttrs.o SLPFindSrvTypes.o SLPFindSrvs.o SLPOpen.o \
		SLPReg.o SLPUtils.o SLPParseSrvURL.o SLPGetRefreshInterval.o \
		slp_queue.o slp_utils.o slp_search.o slp_ua_common.o slp_net.o \
		slp_net_utils.o slp_ipc.o slp_config.o slp_utf8.o \
		slp_targets.o slp_da_cache.o slp_jni_support.o DAAdvert.o \
		SAAdvert.o slp_auth.o

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lnsl -lsocket
$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR =	../clib

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../clib -I$(JAVA_ROOT)/include \
		-I$(JAVA_ROOT)/include/solaris

CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses

# not linted
SMATCH=off

.KEEP_STATE:

all:

lint: lintcheck

include ../../Makefile.targ
