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

include 	../Makefile.sp

MANIFEST=		rfc1179.xml cleanup.xml
ROOTMANIFESTDIR=	$(ROOTSVCAPPLICATIONPRINT)
$(ROOTMANIFEST)		:= FILEMODE= 444

ROOTMETHOD=				$(ROOTLIBSVCMETHOD)/print-cleanup
$(ROOTLIBSVCMETHOD)/print-cleanup	:=	FILEMODE=555

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
		$(ROOTMETHOD) $(ROOTLIBPRINT)

check:	$(CHKMANIFEST)

strip:		$(SUBDIRS)
		$(STRIP) $(PRINTDPROG) $(INLPDPROG)

cstyle:
		cstyle $(PRINTDSRCS) $(INLPDSRCS)

lint:
		$(LINT.c) $(PRINTDSRCS) $(LDLIBS)
		$(LINT.c) $(INLPDSRCS) $(LDLIBS)

clean clobber:	$(SUBDIRS)
		$(RM) $(PRINTDOBJS) $(INLPDOBJS)

_msg:
		@echo "Messages are made in usr/src/cmd/print"

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:



# 
# PRINTSYMLINK=	$(ROOTLIB)/print/printd
# 
# FILEMODE=	04511
# OWNER=		root
# 
# CPPFLAGS +=	-I$(NPRTINC)
# LDLIBS +=	$(LIBNPRT)
# 
# install:	all $(ROOTBIN) $(ROOTLIB)/print $(ROOTBINPROG) \
# 		$(ROOTUSRBINSYMLINK) $(ROOTUSRUCBSYMLINK) $(PRINTSYMLINK) \
# 		$(ROOTMANIFEST) $(ROOTMETHOD)
