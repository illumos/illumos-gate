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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

NETYPPROG =	rpc.ypupdated
PROG =		$(NETYPPROG)

MANIFEST =	update.xml

include ../../Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCNETWORKNIS)

#installed directories
RPCSVC=		$(ROOT)/usr/include/rpcsvc
NETSVC =	$(ROOTLIB)/netsvc
NETYP =		$(NETSVC)/yp
ROOTDIRS =	$(NETSVC) $(NETYP)

# include library definitions
LDLIBS +=	-lnsl

# include path to yptol.h (for name of N2L mapping file)
CPPFLAGS += -I$(SRC)/lib/libnisdb/yptol

INETYPPROG=		$(NETYPPROG:%=$(NETYP)/%)

RPCYPUPDATEOBJ =	rpc.ypupdated.o openchild.o

OBJS =			$(RPCYPUPDATEOBJ)

SRCS =			$(OBJS:%.o=%.c)

CERRWARN +=		-_gcc=-Wno-implicit-function-declaration
CERRWARN +=		-_gcc=-Wno-unused-variable

CLOBBERFILES += ypupdated_prot.h

#conditional assignments
$(INETSVC)   := FILEMODE=555

#install rules

.KEEP_STATE:

all: $(PROG)

ypupdated_prot.h: ypupdate_prot.x
	$(RM) ypupdated_prot.h; $(RPCGEN) -C -h ypupdate_prot.x -o ypupdated_prot.h

$(RPCYPUPDATEOBJ): ypupdated_prot.h

rpc.ypupdated: $(RPCYPUPDATEOBJ)
	$(LINK.c) -o $@ $(RPCYPUPDATEOBJ) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTDIRS) $(IBINPROG) $(INETYPPROG) $(ROOTMANIFEST)

$(ROOTDIRS):
	$(INS.dir)

$(NETYP)/%: %
	$(INS.file)

clean:
	$(RM) $(OBJS)

lint:
	${LINT.c} ${SRCS}

check: $(CHKMANIFEST)

cstyle:
	${CSTYLE} ${SRCS}

# include library targets
include ../../Makefile.targ
