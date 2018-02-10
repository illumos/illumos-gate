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
# Makefile for name service cache daemon
#

PROG=		nscd
MANIFEST=	name-service-cache.xml
SVCMETHOD=	svc-nscd

include ../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)

OBJS=	server.o getpw.o getgr.o gethost.o getnode.o \
	getether.o getrpc.o getproto.o getnet.o \
	getbootp.o getauth.o getserv.o \
	getnetmasks.o getprinter.o getproject.o \
	getexec.o getprof.o getuser.o cache.o \
	nscd_biggest.o nscd_wait.o \
	nscd_init.o nscd_access.o nscd_cfgfile.o nscd_config.o \
	nscd_dbimpl.o nscd_getentctx.o nscd_intaddr.o \
	nscd_log.o nscd_nswconfig.o nscd_nswstate.o nscd_nswcfgst.o \
	nscd_seqnum.o nscd_smfmonitor.o \
	nscd_switch.o nscd_nswparse.o nscd_initf.o nscd_selfcred.o \
	nscd_frontend.o nscd_admin.o nscd_door.o \
	gettnrhtp.o gettnrhdb.o

CLOBBERFILES=	nscd

SRCS=	${OBJS:%.o=%.c}

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -DSUN_THREADS \
		-I../../lib/libc/port/gen -I../../lib/libc/inc \
		-I../../lib/libsldap/common
LINTFLAGS +=	-erroff=E_GLOBAL_COULD_BE_STATIC2
LINTFLAGS +=	-erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS +=	-erroff=E_NAME_DEF_NOT_USED2

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-type-limits

# nscd interposes on many symbols, and must export others for its own dlsym()
# use, and dlsym() calls from libc.  Itemizing the interfaces within a mapfile
# is error-prone, so establish the whole object as an interposer.
LDFLAGS +=	$(ZINTERPOSE)

# TCOV_FLAG=	-ql

PROGLIBS=	$(LDLIBS) -lresolv -lnsl -lsocket -lumem -lscf -lavl

# install macros and rule
#
ROOTPROG=	${ROOTUSRSBIN}/nscd

.KEEP_STATE:

all: $(PROG) $(NISPROG)

${PROG}: ${OBJS}
	${LINK.c} ${OPT} -o $@ ${OBJS} ${PROGLIBS}
	${POST_PROCESS}

lint:
	$(LINT.c) ${SRCS} ${PROGLIBS}

cstyle:
	${CSTYLE} ${SRCS}

install: all $(ROOTPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

clean:
	${RM} ${OBJS}

${ROOTUSRSBIN}/%: %
	${INS.file}

${ROOTUSRLIB}/%: %
	${INS.file}

include ../Makefile.targ
