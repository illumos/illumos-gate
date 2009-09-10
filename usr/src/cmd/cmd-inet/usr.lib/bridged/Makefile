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
# cmd/cmd-inet/usr.lib/bridged/Makefile
#

PROG=		bridged
MANIFEST=	bridge.xml
OBJS=		dlpi.o door.o events.o main.o rstp.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

ROOTMANIFESTDIR= $(ROOTSVCNETWORK)

.KEEP_STATE:

all:		$(PROG)

LDLIBS +=	-lsocket -lrstp -ldlpi -ldladm -lumem
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D__SUN__

.PARALLEL:	$(OBJS)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

include		../Makefile.lib

install:	$(PROG) $(ROOTLIBPROG) $(ROOTMANIFEST)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include		../../../Makefile.targ
