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

PROG=	ldap_cachemgr

MANIFEST=	client.xml
SVCMETHOD=	ldap-client

include ../Makefile.cmd

#
# To compile in the $mgr SLP support
# 1. add -DSLP in to CPPFLAGS line
# 2. add cachemgr_discovery.o to the OBJS line
# 3. add -lslp in the LDLIBS line
#

ROOTLDAPLIB=	$(ROOT)/usr/lib/ldap
ROOTLDAPPROG=	$(PROG:%=$(ROOTLDAPLIB)/%)

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKLDAP)

OBJS=	cachemgr.o cachemgr_getldap.o cachemgr_parse.o cachemgr_change.o

SRCS=	${OBJS:%.o=%.c} 

CPPFLAGS += 	-D_REENTRANT -DSUN_THREADS \
		-I$(SRC)/lib/libsldap/common \
		-I$(SRC)/lib/libldap5/include/ldap \
		-I$(SRC)/lib/libc/port/gen

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-uninitialized

# Message files
POFILE=		ldap_cachemgr.po
POFILES=	${OBJS:%.o=%.po}

LINTOUT=        lint.out

# TCOV_FLAG=	-ql
# GPROF_FLAG=	-xpg
# DEBUG_FLAG=	-g

LDLIBS += 	-lumem -lsldap

# install macros and rule
#

.KEEP_STATE:

clean := TARGET= clean
clobber := TARGET= clobber

$(ROOTSVCMETHOD) := FILEMODE = 0555

all: $(PROG)

${PROG}: ${OBJS}
	${LINK.c} ${OPT} -o $@ ${OBJS} ${LDLIBS}
	${POST_PROCESS}

$(ROOTLDAPLIB):
	$(INS.dir)

$(ROOTLDAPLIB)/%:	%
	$(INS.file)

lint :=	LINTFLAGS=-x -b -u -h

lint:
	$(LINT.c) ${SRCS}  > $(LINTOUT) 2>&1

cstyle:
	${CSTYLE} ${SRCS}

install: all $(ROOTLDAPLIB) $(ROOTLDAPPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS) $(LINTOUT)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

include $(SRC)/cmd/Makefile.targ
