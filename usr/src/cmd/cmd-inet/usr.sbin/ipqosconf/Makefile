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

PROG=		ipqosconf
OBJS=		ipqosconf.o
SRCS=		$(OBJS:%.o=%.c)
HDRS=		ipqosconf.h

MODS=		dlcosmk		\
		flowacct	\
		ipgpc		\
		dscpmk		\
		tokenmt		\
		tswtclmt

TYPES=		$(MODS:%=%.types)

ROOTLIBIPQOSCONF=	$(ROOTLIB)/ipqosconf
ROOTLIBIPQOSCONFTYPES =	$(TYPES:%=$(ROOTLIBIPQOSCONF)/%)

include	../../../Makefile.cmd
include	../../Makefile.cmd-inet

$(ROOTUSRSBIN)/$(PROG)		:=	FILEMODE= 0755
$(ROOTLIBIPQOSCONFTYPES)	:=	FILEMODE= 0444

#pull in prototype for strtok_r
CPPFLAGS +=	-D__EXTENSIONS__
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

LDLIBS +=	-lsocket -lnsl -lnvpair -lipp

.KEEP_STATE:

.INIT:	$(HDRS)

all:	$(PROG)

$(PROG):	$(OBJS) $(HDRS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install:	all $(ROOTUSRSBINPROG) $(ROOTLIBIPQOSCONF) .WAIT \
		$(ROOTLIBIPQOSCONFTYPES)

$(ROOTLIBIPQOSCONF):
	$(INS.dir)

$(ROOTLIBIPQOSCONF)/%:	%
	$(INS.file)

clean:	
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../../Makefile.targ
