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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

DYNPROG= svadm svboot

include ../../Makefile.cmd
include ../Makefile.com

PROG = $(DYNPROG)
LPROG = $(PROG:%=%.li)

SUBDIRS= etc

svadm	:= POBJS = svadm.o
svboot	:= POBJS = svboot.o

OBJS=	svadm.o svboot.o
SRCS=	$(OBJS:%.o=%.c)
POFILE = sv_all.po
POFILES = $(OBJS:%.o=%.po)

svadm	:= LDLIBS += -lunistat -ldscfg
svboot	:= LDLIBS += -lunistat -ldscfg

CFLAGS += -v
LINTFLAGS += -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -erroff=E_SEC_SCANF_UNBOUNDED_COPY
LINTFLAGS += -erroff=E_SEC_PRINTF_VAR_FMT

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(SUBDIRS) $(PROG) $(POFILES) 

install: $(SUBDIRS) all $(ROOTPROG)

lint:	$(SUBDIRS) $(LPROG)

clean:	$(SUBDIRS)
	$(RM) *.o $(POFILE)

$(PROG): $$(POBJS)
	$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(LPROG):
	$(LINT.c) $(@:%.li=%.c) $(LDLIBS)

FRC:

include ../../Makefile.targ
