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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG=		protocmp
STD_OBJS=	proto_list.o protodir.o list.o stdusers.o \
		exception_list.o arch.o depend.o
CMP_OBJS=	protocmp.o $(STD_OBJS)
CMP_SRCS=	$(CMP_OBJS:%.o=%.c)
CLEANFILES +=	$(CMP_OBJS)

include ../Makefile.tools

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused

.KEEP_STATE:

all:	$(PROG)

protocmp: $(CMP_OBJS)
	$(LINK.c) -o $@ $(CMP_OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTONBLDMACHPROG)

lint:	FRC
	$(LINT.c) $(CMP_SRCS)

FRC:

clean:
	$(RM) $(CLEANFILES)

include ../Makefile.targ
