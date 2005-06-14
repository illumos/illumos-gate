#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=	nscd
NISPROG=	nscd_nischeck
MANIFEST=	name-service-cache.xml
SVCMETHOD=	svc-nscd

include ../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)
$(ROOTMANIFEST)		:= FILEMODE= 444

$(ROOTMANIFESTDIR)/%: %
		$(INS.file)

OBJS=	server.o getpw.o getgr.o gethost.o getnode.o hash.o \
	nscd_biggest.o nscd_parse.o nscd_wait.o \
	getexec.o getprof.o getuser.o attrstr.o

NISOBJS=	nscd_nischeck.o  

CLOBBERFILES=	nscd nscd_nischeck

SRCS=	${OBJS:%.o=%.c} 

NISSRC=	${NISOBJS:%.o=%.c}

CPPFLAGS += 	-D_REENTRANT -DSUN_THREADS

# TCOV_FLAG=	-ql
# GPROF_FLAG=	-xpg
# DEBUG_FLAG=	-g

$(PROG) :=	LDLIBS += -lresolv -lnsl -lsocket -lumem -lscf
$(NISPROG) :=	LDLIBS += -lnsl

# install macros and rule
#
GROUP=	bin
ROOTPROG=	${ROOTUSRSBIN}/nscd
ROOTNISPROG=	${ROOTLIB}/nscd_nischeck

.KEEP_STATE:

all: $(PROG) $(NISPROG)

${PROG}: ${OBJS}
	${LINK.c} ${OPT} -o $@ ${OBJS} ${LDLIBS}
	${POST_PROCESS}

${NISPROG}: ${NISOBJS}
	${LINK.c} ${OPT} -o $@ ${NISOBJS} ${LDLIBS}
	${POST_PROCESS}

lint :=	LINTFLAGS=-x -b -u

lint:
	$(LINT.c) ${SRCS}

lint2:
	 $(LINT.c) ${NISSRC}

cstyle:
	${CSTYLE} ${SRCS} ${NISSRC}

install: all $(ROOTPROG) $(ROOTNISPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

clean:
	${RM} ${OBJS} ${NISOBJS}

${ROOTUSRSBIN}/%: %
	${INS.file}

${ROOTUSRLIB}/%: %
	${INS.file}



include ../Makefile.targ



