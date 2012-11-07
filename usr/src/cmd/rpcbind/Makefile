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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		rpcbind
MANIFEST=	bind.xml
SVCMETHOD=	rpc-bind

OBJS= check_bound.o pmap_svc.o rpcb_svc.o rpcb_svc_com.o rpcb_svc_4.o \
	 rpcb_stat.o rpcbind.o warmstart.o selfcheck.o rpcb_check.o

CLOBBERFILES += $(SVCMETHOD)

SRC1= $(OBJS:%.o=%.c)
SRCS= $(SRC1:selfcheck.c=../fs.d/nfs/lib/selfcheck.c)

include ../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKRPC)

CPPFLAGS= -I. -DPORTMAP $(CPPFLAGS.master)
CPPFLAGS += -D_REENTRANT
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-label
LDLIBS += -lsocket -lnsl -lwrap -lscf

.KEEP_STATE:

all: $(PROG) $(SVCMETHOD)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

selfcheck.o:    ../fs.d/nfs/lib/selfcheck.c
		$(COMPILE.c) ../fs.d/nfs/lib/selfcheck.c
		$(POST_PROCESS_O)

install: all $(ROOTUSRSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../Makefile.targ
