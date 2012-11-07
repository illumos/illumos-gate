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

DYNPROG = dscfglockd dscfgcli

include ../../Makefile.cmd
include ../Makefile.com

PROG = $(DYNPROG)

dscfglockd	:= POBJS = dscfglockd.o

dscfgcli	:= POBJS = dscfgcli.o

OBJS=	dscfglockd.o dscfgcli.o
SRCS=	$(OBJS:%.o=%.c)
POFILES= $(OBJS:%.o=%.po)

dscfgcli	:= LDLIBS += -ldscfg -lnsl
dscfglockd	:= LDLIBS += -lunistat -ldscfg -lsocket -lnsl

CFLAGS += $(CCVERBOSE) -D_RDC_ -D_SYSCALL32
CERRWARN += -_gcc=-Wno-switch
LINTFLAGS += -Xa -n -s -x -m -u -Dlint -errhdr=%user -D_RDC_ -D_SYSCALL32
LINTFLAGS += -DDEBUG -erroff=E_SEC_SCANF_UNBOUNDED_COPY
LINTDIR = $(KBASE)/lintdir
POFILE = dscfglockd_all.po
LFILE = $(LINTDIR)/rdc.ln
ROOTLINK = $(ROOTLIB)/dscfglockd

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(SUBDIRS) $(PROG) $(POFILES)

install: $(SUBDIRS) all $(ROOTPROG) $(ROOTLINK)

lint:	$(SUBDIRS) lint_SRCS

clean:	$(SUBDIRS)
	$(RM) *.o $(POFILES)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(PROG):	$$(POBJS)
	$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTLINK):	$(ROOTLIB) $(ROOTBIN)/dscfglockd
	-$(RM) $@; $(LN) $(ROOTBIN)/dscfglockd $@

FRC:

include	../../Makefile.targ
