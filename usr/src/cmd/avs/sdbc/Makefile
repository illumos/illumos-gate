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

# must be before include of Makefile.cmd
DYNPROG = scmadm \
	sd_stats \
	sd_diag

include ../../Makefile.cmd
include ../Makefile.com

SUBDIRS=	etc

PROG = $(DYNPROG)

scmadm		:= POBJS = scmadm.o sdbc_ioctl.o
sd_stats	:= POBJS = sd_stats.o sd_trace.o sdbc_ioctl.o rdc_ioctl.o
sd_diag		:= POBJS = sd_diag.o
sdbc_dynmem	:= POBJS = sdbc_dynmem.o

OBJS=	scmadm.o\
	sdbc_ioctl.o\
	sd_diag.o\
	sd_stats.o\
	sd_trace.o\
	sdbc_dynmem.o

XTRA_OBJS= \
	rdc_ioctl.o

SRCS=	$(OBJS:%.o=%.c)

POFILE =	scmadm.po

scmadm		:= LDLIBS += -lnsctl -lunistat -ldscfg
sd_stats	:= LDLIBS += -lunistat -lcurses
sd_diag		:= LDLIBS += -lnsctl
sdbc_dynmem	:= LDLIBS += -lkstat

CFLAGS +=	$(CCVERBOSE) -D_SCM_ -D_SD_8K_BLKSIZE -D_SYSCALL32
CPPFLAGS +=	-DNSC_MULTI_TERABYTE
LINTFLAGS +=	-Xa -n -s -x -m -u -Dlint -errhdr=%user
LINTFLAGS +=	-D_SCM_ -D_SD_8K_BLKSIZE -D_SYSCALL32
LINTFLAGS +=	-erroff=E_SEC_PRINTF_VAR_FMT
LINTFLAGS +=	-erroff=E_SEC_SPRINTF_UNBOUNDED_COPY
LINTFLAGS +=	-erroff=E_SEC_SCANF_UNBOUNDED_COPY
LINTFLAGS +=	-erroff=E_SEC_FORBIDDEN_WARN_ASCFTIME
LINTFLAGS +=	-DDEBUG
CERRWARN +=	-_gcc=-Wno-uninitialized
ROOTLINK = $(ROOTUSRSBIN)/scmadm

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.KEEP_STATE:

.PARALLEL: $(OBJS) $(XTRA_OBJS)

all:	$(SUBDIRS) $(PROG) $(POFILE)

install: $(SUBDIRS) all $(ROOTPROG) $(ROOTLINK)

lint:	$(SUBDIRS) lint_SRCS

clean:	$(SUBDIRS)
	$(RM) *.o

rdc_ioctl.o: ../rdc/rdc_ioctl.c
	$(COMPILE.c) ../rdc/rdc_ioctl.c

$(PROG):	$$(POBJS)
	$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTLINK): $(ROOTUSRSBIN) $(ROOTBIN)/scmadm
	-$(RM) $@; $(LN) $(ROOTBIN)/scmadm $@

include ../../Makefile.targ

FRC:
