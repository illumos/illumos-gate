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


PROG=	smbd
OBJS=				\
	smbd_authsvc.o		\
	smbd_doorsvc.o		\
	smbd_join.o		\
	smbd_krb5lookup.o	\
	smbd_krb5ssp.o		\
	smbd_logon.o		\
	smbd_main.o		\
	smbd_nicmon.o		\
	smbd_ntlmssp.o		\
	smbd_pipesvc.o		\
	smbd_share_doorsvc.o	\
	smbd_spool.o		\
	smbd_syslog.o		\
	smbd_vss.o

SRCS=	$(OBJS:%.o=%.c)

include ../../Makefile.cmd

MANIFEST=	server.xml
SVCMETHOD=	svc-smbd
LOGDLL=		eventlog.dll

ROOTMANIFESTDIR	= $(ROOTSVCSMB)
ROOTVARSMBDLLDIR = $(ROOTVARSMB)/cvol/windows/system32
ROOTVARSMBDLL= $(LOGDLL:%=$(ROOTVARSMBDLLDIR)/%)

$(ROOTMANIFEST):= FILEMODE = 0444
$(ROOTSVCMETHOD):= FILEMODE = 0555
$(ROOTVARSMBDLL):= FILEMODE = 0755

LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS += -xerroff=E_NAME_USED_NOT_DEF2

CFLAGS += $(CCVERBOSE)
CPPFLAGS += -D_IPP_PRIVATE_STRUCTURES
CPPFLAGS += -D_REENTRANT
CPPFLAGS += -Dsyslog=smb_syslog
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

# Should not have to do this, but the Kerberos includes are a mess.
CPPFLAGS += -I $(ROOT)/usr/include/kerberosv5

CSTD =       $(CSTD_GNU99)
C99LMODE =      -Xc99=%all

LDFLAGS += -R/usr/lib/smbsrv
LDLIBS += -L$(ROOT)/usr/lib/smbsrv
# prefer to keep libs ordered by dependence
LDLIBS += -lmlsvc -lmlrpc -lsmbns -lsmb -lsmbfs -lgss
LDLIBS += -lzfs -lbsm -lscf -lcmdutils -lsocket -lnsl -lumem
$(PROG) := LDLIBS += -lkrb5

$(ENABLE_SMB_PRINTING) CPPFLAGS += -DHAVE_CUPS

ROOTSMBDDIR = $(ROOTLIB)/smbsrv
ROOTSMBDFILE = $(PROG:%=$(ROOTSMBDDIR)/%)

FILEMODE = 0444
$(ROOTSMBDFILE):= FILEMODE = 0555

$(ROOTSMBDDIR)/%: %
	$(INS.file)

$(ROOTVARSMBDLLDIR)/%: %
	$(INS.file)

all:		$(PROG)

clean:
	$(RM) $(OBJS)

lint:		lint_SRCS

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

check:		$(CHKMANIFEST)

_msg:

include ../../Makefile.targ

install: all .WAIT $(ROOTETCDEFAULTFILES) $(ROOTMANIFEST) \
		$(ROOTSMBDFILE) ${ROOTSVCMETHOD} $(ROOTVARSMBDLL)

.KEEP_STATE:
