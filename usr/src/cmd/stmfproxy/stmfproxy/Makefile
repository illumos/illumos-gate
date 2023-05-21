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
#
# cmd/stmfproxy/stmfproxy/Makefile
#

PROG	= svc-stmfproxy

COMMONBASE = ../../common

include ../../Makefile.cmd

DEMOFILES = \
	stmfproxy.xml

DEMOBINFILES = \
	$(PROG)

ROOTDEMODIR	= $(ROOT)/usr/demo/comstar
ROOTDEMOBINDIR	= $(ROOTDEMODIR)/bin
ROOTDEMOFILES = $(DEMOFILES:%=$(ROOTDEMODIR)/%)
ROOTDEMOBINFILES = $(DEMOBINFILES:%=$(ROOTDEMOBINDIR)/%)

PRODUCT=	$(PROG)
SRCS=		$(OBJS:%.o=./%.c)
OBJS=		stmfproxy.o
LLOBJS=		$(OBJS:%.o=%.ll)

$(ROOTDEMODIR)/stmfproxy.xml	:= FILEMODE = 0444


CCVERBOSE	=
LDLIBS += -lnsl -lstmf -lstmfproxy
CPPFLAGS += -I. -I$(COMMONBASE)/cmdparse

.KEEP_STATE:

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

.PARALLEL: $(OBJS)

all:	$(PROG)

clean:
	$(RM) $(PROG) $(OBJS) $(LLOBJS)

install: all $(ROOTDEMOFILES) $(ROOTDEMOBINFILES)

$(ROOTDEMODIR) $(ROOTDEMOBINDIR):
	$(INS.dir)

$(ROOTDEMODIR)/% $(ROOTDEMOBINDIR)/% : %
	$(INS.file)

$(ROOTDEMOFILES): $(ROOTDEMODIR)

$(ROOTDEMOBINFILES): $(ROOTDEMOBINDIR)

check:	$(CHKMANIFEST)
	$(CSTYLE) -pPc $(SRCS:%=%)


include ../../Makefile.targ
