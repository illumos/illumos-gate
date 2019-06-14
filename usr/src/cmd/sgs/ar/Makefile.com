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
# Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG=		ar
XPG4PROG=	ar

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com

COMOBJ=		main.o		file.o		cmd.o

BLTOBJ =	msg.o

OBJS=		$(BLTOBJ:%=objs/%) $(COMOBJ:%=objs/%)
XPG4OBJS=	$(BLTOBJ:%=objs.xpg4/%) $(COMOBJ:%=objs.xpg4/%)

LLDFLAGS =	'-R$$ORIGIN/../../lib'
LLDFLAGS64 =	'-R$$ORIGIN/../../../lib/$(MACH64)'
CPPFLAGS=	-I. -I../../include $(CPPFLAGS.master) -I$(ELFCAP)
CFLAGS +=	$(CCVERBOSE)
CSTD=	$(CSTD_GNU99)

CERRWARN +=	$(CNOWARN_UNINIT)

SMOFF += signed

LDLIBS +=	-lelf $(CONVLIBDIR) -lconv -lsendfile

$(XPG4) :=	CPPFLAGS += -DXPG4

BLTDEFS =	msg.h
BLTDATA =	msg.c
BLTMESG =	$(SGSMSGDIR)/ar

BLTFILES =	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM =	../common/ar.msg
SGSMSGTARG =	$(SGSMSGCOM)
SGSMSGALL =	$(SGSMSGCOM)

SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n ar_msg

SRCS=		$(COMOBJ:%.o=../common/%.c) $(BLTDATA:%.o=$(SGSCOMMON)/%.c)

CLEANFILES +=	$(BLTFILES)
