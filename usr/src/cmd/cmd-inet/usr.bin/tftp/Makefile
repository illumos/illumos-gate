#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright (c) 1989,2001 by Sun Microsystems, Inc.
# All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.

PROG=	tftp
OBJS=	main.o tftp.o tftpsubs.o
SRCS= $(OBJS:%.o=%.c)

include ../../../Makefile.cmd
include ../../Makefile.cmd-inet

MANIFEST=    tftp-udp6.xml

ROOTMANIFESTDIR = $(ROOTSVCNETWORK)

$(ROOTMANIFEST):= FILEMODE = 0444

CPPFLAGS +=	-DSYSV -DSTRNET -DBSD_COMP -I$(CMDINETCOMMONDIR)
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-parentheses
LDLIBS +=	-lsocket -lnsl

.KEEP_STATE:

all: $(PROG) 

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG) $(ROOTMANIFEST)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

check:		$(CHKMANIFEST)

include ../../../Makefile.targ
