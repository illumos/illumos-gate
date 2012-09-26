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

include ../../Makefile.cmd
include ../Makefile.com

DYNPROG =	iiadm iiboot iicpbmp iicpshd

PROG=$(DYNPROG)

PROG1 = iiadm
PROG2 = iiboot
PROG3 = iicpbmp
PROG4 = iicpshd

SUBDIRS= etc

iiadm	:= POBJS = iiadm.o
iiboot	:= POBJS = iiboot.o
iicpbmp	:= POBJS = iicpbmp.o
iicpshd	:= POBJS = iicpshd.o

iiadm   := LDLIBS += -lnsctl -ldscfg -lunistat -lm
iiboot  := LDLIBS += -ldscfg -lunistat
iicpbmp := LDLIBS += -ldscfg -lunistat
iicpshd := LDLIBS += -ldscfg -lunistat

OBJS=	iiadm.o iiboot.o iicpbmp.o iicpshd.o
POFILE = dsw_all.po
SRCS=	$(OBJS:%.o=%.c)
POFILES= $(OBJS:%.o=%.po)

CFLAGS +=	$(CCVERBOSE) -D_DSW_
LINTFLAGS +=	-Xa -n -s -x -m -u -Dlint -errhdr=%user -D_DSW_ -DDEBUG
LINTFLAGS +=	-erroff=E_SEC_SCANF_UNBOUNDED_COPY
LINTFLAGS +=	-erroff=E_SEC_PRINTF_VAR_FMT
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(SUBDIRS) $(PROG) $(POFILES)

install: $(SUBDIRS) all $(ROOTPROG)
	-$(RM) $(ROOT)/usr/sbin/$(PROG1)
	-$(RM) $(ROOT)/usr/sbin/$(PROG2)
	-$(RM) $(ROOT)/usr/sbin/$(PROG3)
	-$(RM) $(ROOT)/usr/sbin/$(PROG4)
	-$(SYMLINK) ../bin/$(PROG1) $(ROOT)/usr/sbin/$(PROG1)
	-$(SYMLINK) ../bin/$(PROG2) $(ROOT)/usr/sbin/$(PROG2)
	-$(SYMLINK) ../bin/$(PROG3) $(ROOT)/usr/sbin/$(PROG3)
	-$(SYMLINK) ../bin/$(PROG4) $(ROOT)/usr/sbin/$(PROG4)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

lint:	$(SUBDIRS) lint_SRCS

clean:	$(SUBDIRS)
	$(RM) *.o $(POFILES)

$(PROG): $(OBJS)
	$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include	../../Makefile.targ
