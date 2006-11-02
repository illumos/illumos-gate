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
# pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# server/gateway/adaptor/Makefile
#

MANIFEST=		rfc1179.xml cleanup.xml
SVCMETHOD=		print-cleanup

include		../Makefile.sp

ROOTMANIFESTDIR=	$(ROOTSVCAPPLICATIONPRINT)

ROOTLIBPRINT=		$(ROOTLIB)/print
$(ROOTLIBPRINT)		:=	OWNER=root
$(ROOTLIBPRINT)		:=	GROUP=lp

PRINTDPROG=		printd
PRINTDSRCS=		printd.c
PRINTDOBJS=		$(PRINTDSRCS:.c=.o)
$(PRINTDPROG)		:=	LDLIBS +=	$(LIBNPRT)
$(ROOTLIBPRINT)/$(PRINTDPROG)		:=	FILEMODE=	555

INLPDPROG=		in.lpd
INLPDSRCS= 		main.c adaptor.c
INLPDOBJS=		$(INLPDSRCS:.c=.o)
$(INLPDPROG)		:=	LDLIBS +=	-lsocket -lnsl $(LIBNPRT)

PROG=		$(PRINTDPROG) $(INLPDPROG)

SUBDIRS=	translators

FILEMODE=	0555
OWNER=		root
GROUP=		bin


CPPFLAGS +=	-I. -I$(NPRTINC) #$(CPPFLAGS.master)

.KEEP_STATE:

all:		$(PRINTDPROG) $(INLPDPROG) $(SUBDIRS)

$(PRINTDPROG):	$(PRINTDOBJS)
		$(LINK.c) $(PRINTDOBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(INLPDPROG):	$(INLPDOBJS)
		$(LINK.c) $(INLPDOBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

ROOTLIBPRINTPROG=	$(PRINTDPROG:%=$(ROOTLIBPRINT)/%) \
			$(INLPDPROG:%=$(ROOTLIBPRINT)/%)

install:	all $(ROOTLIBPRINTPROG) $(SUBDIRS) $(ROOTMANIFEST) \
		$(ROOTSVCMETHOD) $(ROOTLIBPRINT)

check:	$(CHKMANIFEST)

strip:		$(SUBDIRS)
		$(STRIP) $(PRINTDPROG) $(INLPDPROG)

cstyle:
		cstyle $(PRINTDSRCS) $(INLPDSRCS)

lint:
		$(LINT.c) $(PRINTDSRCS) $(LDLIBS)
		$(LINT.c) $(INLPDSRCS) $(LDLIBS)

clean:		$(SUBDIRS)
		$(RM) $(PRINTDOBJS) $(INLPDOBJS)

clobber:	clean $(SUBDIRS)

_msg:
		@echo "Messages are made in usr/src/cmd/print"

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include		$(SRC)/cmd/Makefile.targ
