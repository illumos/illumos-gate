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

.KEEP_STATE:

PROG = dscfg
SHFILES = dscfgadm
CLOBBERFILES = $(SHFILES)

include ../../Makefile.cmd
include ../Makefile.com


LPROG = $(PROG:%=%.li)

SUBDIRS= etc

OBJS=	dscfg.o	

CFLAGS += $(CCVERBOSE) -D_SYSCALL32
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-address
LDLIBS += -ldscfg -lunistat
LINTFLAGS += -Xa -n -s -x -m -u -Dlint -errhdr=%user -D_SYSCALL32
LINTFLAGS += -erroff=E_NOP_ELSE_STMT -erroff=E_FUNC_SET_NOT_USED
LINTFLAGS += -erroff=E_BAD_FORMAT_ARG_TYPE2
LINTFLAGS += -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTFLAGS += -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTDIR = $(KBASE)/lintdir
LFILE = $(LINTDIR)/dscfg.ln
ROOTLINK = $(ROOTUSRSBIN)/$(PROG)
ROOTSHLINK = $(ROOTUSRSBIN)/$(SHFILES)

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

all: $(SUBDIRS) $(PROG) $(SHFILES)

install: $(SUBDIRS) all $(ROOTSHFILES) $(ROOTPROG) $(ROOTLINK) $(ROOTSHLINK)

lint:	$(SUBDIRS) lint_PROG

clean:	$(SUBDIRS)
	$(RM) *.o

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTLINK):	$(ROOTUSRSBIN) $(ROOTPROG)
	-$(RM) $@; $(LN) $(ROOTPROG) $@

$(ROOTSHLINK):	$(ROOTUSRSBIN) $(ROOTSHFILES)
	-$(RM) $@; $(LN) $(ROOTSHFILES) $@

FRC:

include	../../Makefile.targ
