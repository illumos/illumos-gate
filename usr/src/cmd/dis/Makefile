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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=	dis
OBJS=	dis_target.o dis_main.o dis_util.o dis_list.o
SRCS=	$(OBJS:%.o=%.c)

include 	../Makefile.cmd

LDLIBS += -ldisasm -luutil -lelf
CERRWARN += -_gcc=-Wno-uninitialized

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG) $(ROOTCCSBINLINK)

clean:
	$(RM) $(OBJS) $(PROG)

lint: lint_SRCS

include ../Makefile.targ
include ../Makefile.ctf
