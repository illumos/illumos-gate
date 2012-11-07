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

DYNPROG = sndrd sndradm sndrboot sndrsyncd

include ../../Makefile.cmd
include ../Makefile.com

PROG = $(DYNPROG)

SUBDIRS=	etc

sndradm		:= POBJS = sndradm.o rdc_ioctl.o sndrsubr.o
sndrboot	:= POBJS = sndrboot.o rdc_ioctl.o sndrsubr.o
sndrd		:= POBJS = sndrd.o
sndrsyncd	:= POBJS = sndrsyncd.o rdc_ioctl.o sndrsubr.o

OBJS=	\
	sndrboot.o \
	sndradm.o \
	sndrd.o \
	sndrsyncd.o \
	rdc_ioctl.o \
	sndrsubr.o

XTRA_OBJS= \
	sdbc_ioctl.o

SRCS=	$(OBJS:%.o=%.c) ../sdbc/sdbc_ioctl.c

sndradm		:= LDLIBS += -lrdc -lunistat -ldscfg -lnsctl -lnsl
sndrboot	:= LDLIBS += -lrdc -lunistat -ldscfg
sndrd		:= LDLIBS += -lrdc -lnsl
sndrsyncd	:= LDLIBS += -lrdc -ldscfg -lunistat

CFLAGS += $(CCVERBOSE) -D_RDC_ -D_SYSCALL32
LINTFLAGS += -Xa -n -s -x -m -u -Dlint -errhdr=%user -D_RDC_ -D_SYSCALL32
LINTFLAGS += -DDEBUG
LINTFLAGS += -erroff=E_SEC_SPRINTF_UNBOUNDED_COPY
LINTFLAGS += -erroff=E_SEC_SCANF_UNBOUNDED_COPY
LINTFLAGS += -erroff=E_SEC_PRINTF_VAR_FMT
LINTFLAGS += -erroff=E_FUNC_SET_NOT_USED
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
POFILE = rdc_all.po
POFILES = sndradm.po sndrboot.po
ROOTLIBLINKS = $(ROOTLIB)/sndrd $(ROOTLIB)/sndrsyncd
ROOTUSRSBINLINKS = $(ROOTUSRSBIN)/sndradm $(ROOTUSRSBIN)/sndrboot

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.KEEP_STATE:

.PARALLEL: $(OBJS) $(XTRA_OBJS)

all: $(SUBDIRS) $(PROG) $(POFILES)

install: $(SUBDIRS) all $(ROOTPROG) $(ROOTLIBLINKS) $(ROOTUSRSBINLINKS)

lint:	$(SUBDIRS) lint_SRCS

clean:	$(SUBDIRS)
	$(RM) *.o $(POFILES)

$(PROG):	$$(POBJS)
	$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

sdbc_ioctl.o: ../sdbc/sdbc_ioctl.c
	$(COMPILE.c) ../sdbc/sdbc_ioctl.c

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTLIBLINKS): $(ROOTLIB) $(ROOTPROG)
	-$(RM) $(ROOTLIBLINKS);
	$(LN) $(ROOTBIN)/sndrd $(ROOTLIB)/sndrd;
	$(LN) $(ROOTBIN)/sndrsyncd $(ROOTLIB)/sndrsyncd

$(ROOTUSRSBINLINKS): $(ROOTUSRSBIN) $(ROOTPROG)
	-$(RM) $(ROOTUSRSBINLINKS);
	$(LN) $(ROOTBIN)/sndradm $(ROOTUSRSBIN)/sndradm;
	$(LN) $(ROOTBIN)/sndrboot $(ROOTUSRSBIN)/sndrboot

FRC:

include	../../Makefile.targ
