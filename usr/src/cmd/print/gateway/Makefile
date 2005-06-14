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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# server/gateway/adaptor/Makefile
#

include 	../Makefile.sp

MANIFEST=	rfc1179.xml

ROOTMANIFESTDIR=	$(ROOTSVCAPPLICATIONPRINT)
$(ROOTMANIFEST)		:= FILEMODE= 444

SUBDIRS=	translators

PROG=		in.lpd

SRCS= 		main.c adaptor.c

OBJS=		$(SRCS:.c=.o)


FILEMODE=	0555
OWNER=		root
GROUP=		bin


CPPFLAGS +=	-I. -I$(NPRTINC) #$(CPPFLAGS.master)
LDLIBS +=	-lsocket -lnsl $(LIBNPRT)

.KEEP_STATE:

all:		$(PROG) $(SUBDIRS)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTLIBPRINTPROG) $(SUBDIRS) $(ROOTMANIFEST)

check:	$(CHKMANIFEST)

strip:		$(SUBDIRS)
		$(STRIP) $(PROG)

cstyle:
		cstyle $(SRCS)

lint:
		$(LINT.c) $(SRCS) $(LDLIBS)

clean clobber:	$(SUBDIRS)
		$(RM) $(OBJS)

_msg:
		@echo "Messages are made in usr/src/cmd/print"

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
