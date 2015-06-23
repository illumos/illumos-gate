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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#


PROG=	fksmbd
OBJS_SMBD=			\
	smbd_doorsvc.o		\
	smbd_join.o		\
	smbd_logon.o		\
	smbd_main.o		\
	smbd_nicmon.o		\
	smbd_pipesvc.o		\
	smbd_share_doorsvc.o	\
	smbd_spool.o		\
	smbd_vss.o		\


OBJS_LOCAL =			\
	fksmbd_door.o		\
	fksmbd_kmod.o		\
	fksmbd_ksock.o		\
	fksmbd_log.o		\
	fksmbd_shr.o

OBJS=	${OBJS_SMBD} ${OBJS_LOCAL}
SRCS=	${OBJS_SMBD:%.o=../smbd/%.c} \
	${OBJS_LOCAL:.o=.c}

include ../../Makefile.cmd
include ../../Makefile.ctf

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
CPPFLAGS.first += -I../../../lib/smbsrv/libfksmbsrv/common

INCS += -I../smbd
INCS +=	-I../../../uts/common
INCS +=	-I../../../uts/common/smbsrv
INCS +=	-I../../../common/smbsrv

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
CPPFLAGS += -D_REENTRANT
CPPFLAGS += -Dsyslog=smb_syslog
CPPFLAGS += -D_LARGEFILE64_SOURCE=1
CPPFLAGS += -DFKSMBD
# Always debug here
CPPFLAGS += -DDEBUG 
CPPFLAGS += $(INCS)

LDFLAGS += $(ZNOLAZYLOAD)
LDFLAGS += -R/usr/lib/smbsrv
LDLIBS += -L$(ROOT)/usr/lib/smbsrv 
LDLIBS += -lfksmbsrv -lfakekernel
LDLIBS += -lmlsvc -lmlrpc -lsmbns -lsmb
LDLIBS += -lzfs -lcmdutils -lbsm -lsocket -lnsl -lscf -lumem

LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS += -xerroff=E_INCONS_ARG_DECL2
LINTFLAGS += -xerroff=E_INCONS_VAL_TYPE_DECL2

ROOTSMBDDIR = $(ROOTLIB)/smbsrv
ROOTSMBDFILE = $(PROG:%=$(ROOTSMBDDIR)/%)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(OBJS)

lint:	lint_SRCS

include ../../Makefile.targ

install: all $(ROOTSMBDFILE)

%.o: ../smbd/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

$(ROOTSMBDDIR)/%: %
	$(INS.file)
