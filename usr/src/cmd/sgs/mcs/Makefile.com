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
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG=		mcs
STRIPFILE=	strip

ROOTLINKS=	$(VAR_SGSBIN)/$(STRIPFILE)

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com

# avoid bootstrap problems
MCS =		/usr/ccs/bin/mcs

COMOBJS =	main.o		file.o		utils.o		global.o \
		message.o
TOOLSOBJS =	alist.o

OBJS =		$(COMOBJS) $(TOOLSOBJS)

LLDFLAGS =	'-R$$ORIGIN/../../lib'
LLDFLAGS64 =	'-R$$ORIGIN/../../../lib/$(MACH64)'
LDFLAGS +=	$(VERSREF) $(LLDFLAGS)
LDLIBS +=	$(CONVLIBDIR) $(CONV_LIB) $(ELFLIBDIR) -lelf

CERRWARN +=	-_gcc=-Wno-uninitialized

SRCS =		$(COMOBJS:%.o=../common/%.c) \
		$(TOOLSOBJS:%.o=$(SGSTOOLS)/common/%.c)

CLEANFILES +=	$(OBJS)
