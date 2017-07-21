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
# Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
#


PROG=	testoplock

OBJS_LOCAL=	tol_main.o tol_misc.o
OBJS_SMBSRV=	smb_cmn_oplock.o
OBJS_LIBSMB=	smb_status_tbl.o

OBJS=	${OBJS_LOCAL} ${OBJS_SMBSRV}  ${OBJS_LIBSMB}

SMBSRV_SRCDIR=../../../uts/common/fs/smbsrv
SRCS=	${OBJS_LOCAL:.o=.c} \
	${OBJS_SMBSRV:%.o=${SMBSRV_SRCDIR}/%.c}

include ../../Makefile.cmd
include ../../Makefile.ctf

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
CPPFLAGS.first += -I.
CPPFLAGS.first += -I../../../lib/libfakekernel/common
CPPFLAGS.first += -I../../../lib/smbsrv/libfksmbsrv/common

INCS +=	-I../../../uts/common

CSTD=		$(CSTD_GNU99)

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)

CPPFLAGS.master=$(DTEXTDOM) $(DTS_ERRNO)

#	CPPFLAGS is deliberatly set with a "=" and not a "+="...
CPPFLAGS=	$(CPPFLAGS.first) $(CPPFLAGS.master)

CPPFLAGS += -D_REENTRANT
CPPFLAGS += -DTESTJIG
CPPFLAGS += -Dsyslog=smb_syslog
CPPFLAGS += -D_LARGEFILE64_SOURCE=1
# Always debug here
CPPFLAGS += -DDEBUG
CPPFLAGS += $(INCS)

LDFLAGS += $(ZNOLAZYLOAD)
LDFLAGS += '-R$$ORIGIN/..'
LDLIBS += -lfakekernel -lcmdutils

LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS += -xerroff=E_NAME_USED_NOT_DEF2
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

lint:	# lint_SRCS

include ../../Makefile.targ

install: all $(ROOTSMBDFILE)


tol_main.o : tol_main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D_KMEMUSER -c tol_main.c
	$(POST_PROCESS_O)

tol_misc.o : tol_misc.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D_FAKE_KERNEL \
	  -I../../../uts/common/smbsrv \
	  -I../../../common/smbsrv -c tol_misc.c
	$(POST_PROCESS_O)

# OBJS_SMBSRV
%.o: ../../../uts/common/fs/smbsrv/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D_FAKE_KERNEL \
	  -I../../../uts/common/smbsrv \
	  -I../../../common/smbsrv -c $<
	$(POST_PROCESS_O)

# OBJS_LIBSMB
%.o: ../../../lib/smbsrv/libsmb/common/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
	$(POST_PROCESS_O)


$(ROOTSMBDDIR)/%: %
	$(INS.file)
