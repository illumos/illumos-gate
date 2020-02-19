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
# Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2020 Joyent, Inc.

NETYPPROG =	rpc.yppasswdd
DEFAULTFILES =	yppasswdd.dfl
PROG =		$(NETYPPROG)

MANIFEST = passwd.xml

include ../../Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCNETWORKNIS)

#installed directories
RPCSVC=		$(ROOT)/usr/include/rpcsvc
NETSVC =	$(ROOTLIB)/netsvc
NETYP =		$(NETSVC)/yp
ROOTDIRS =	$(NETSVC) $(NETYP)

# include library definitions
#LDLIBS +=	-lrpcsvc -lnsl -lcrypt -lintl -lgen
LDLIBS +=	-lnsl -lnisdb -lc
MAPFILES =	$(MAPFILE.INT) $(MAPFILE.NGB)
LDFLAGS +=	$(MAPFILES:%=-M%)

ZGUIDANCE =	-zguidance=nounused

# Pick up includes from library
CPPFLAGS += -I$(SRC)/lib/libnisdb/yptol

# This file is now in the $(SRC)/head/rpcsvc directory.
#HDRFILE= yppasswd.h
#IHDRFILE= $(HDRFILE:%=$(RPCSVC)/%)

INETYPPROG=		$(NETYPPROG:%=$(NETYP)/%)

COMMONOBJ =		yppasswdxdr.o yplckpwdf.o
RPCYPPASSWDDOBJ =	yppasswdd.o changepasswd.o

CERRWARN +=		-_gcc=-Wno-implicit-function-declaration
CERRWARN +=		-_gcc=-Wno-parentheses
CERRWARN +=		$(CNOWARN_UNINIT)

# not linted
SMATCH=off

#
# Objects shared between all the major components
#
SHAREDOBJ= ../shared/utils.o ../shared/lockmap.o ../shared/ancil.o

OBJS = 			$(RPCYPPASSWDDOBJ) \
			$(COMMONOBJ)
			# $(YPPWCONVOBJ) $(YPPASSMGMTOBJ)

SRCS =			$(OBJS:%.o=%.c)

#conditional assignments
$(INETSVC)   := FILEMODE=555

$(ETCDFLTFILE) := FILEMODE=0444

#install rules

.KEEP_STATE:

all: $(PROG)

rpc.yppasswdd: $(RPCYPPASSWDDOBJ) $(COMMONOBJ) $(MAPFILES)
	$(LINK.cc) -o $@ $(RPCYPPASSWDDOBJ) \
	$(SHAREDOBJ) $(COMMONOBJ) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTDIRS) $(IBINPROG) $(INETYPPROG) $(ROOTETCDEFAULTFILES) \
	$(ROOTMANIFEST)

$(ROOTDIRS):
	$(INS.dir)

$(NETYP)/%: %
	$(INS.file)

clean:
	$(RM) $(OBJS)

check: $(CHKMANIFEST)

cstyle:
	${CSTYLE} ${SRCS}

# include library targets
include ../../Makefile.targ
