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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for volume management utilities
#

include ../../Makefile.cmd
include ../Makefile.volmgt

CAT=		cat

OBJS=		eject.o volcancel.o volstat.o volmissing.o volcheck.o \
		volrmmount.o
SRCS=		$(OBJS:%.o=%.c)

LPROG=		volcancel volstat volmissing
BPROG=		eject volcheck volrmmount

volcancel :=	LDLIBS += -lvolmgt
volstat :=	LDLIBS += -lvolmgt
volcheck :=	LDLIBS += -lvolmgt
volrmmount :=	LDLIBS += -lvolmgt
eject :=	LDLIBS += -lvolmgt -ladm

#
# some C source files need vold.h
#

CPPFLAGS += -I${SRC}/cmd/volmgt/vold -D_FILE_OFFSET_BITS=64

# for messaging catalog
#
POFILES=$(LPROG:%=%.po) $(BPROG:%=%.po)
POFILE=util.po

# install macros and rules
#
ROOTBINPROG=	${BPROG:%=${ROOTBIN}/%}
VOLLIBPROG=	${LPROG:%=${VOLLIBDIR}/%}

#
# eject, volrmmount need to be suid root
#
${ROOTBIN}/eject := FILEMODE = 04555
${ROOTBIN}/volrmmount := FILEMODE = 04555
${ROOTBIN}/eject := OWNER = root
${ROOTBIN}/volrmmount := OWNER = root

LINTFLAGS += -errchk=longptr64

.KEEP_STATE:

all: volsetup ${LPROG} ${BPROG}

eject:	eject.o
	${LINK.c} -o $@ eject.o ${LDLIBS}
	$(POST_PROCESS)

volcancel: volcancel.o
	${LINK.c} -o $@ volcancel.o ${LDLIBS}
	$(POST_PROCESS)

volmissing: volmissing.o
	${LINK.c} -o $@ volmissing.o ${LDLIBS}
	$(POST_PROCESS)

volstat: volstat.o
	${LINK.c} -o $@ volstat.o ${LDLIBS}
	$(POST_PROCESS)

volcheck: volcheck.o
	${LINK.c} -o $@ volcheck.o ${LDLIBS}
	$(POST_PROCESS)

volrmmount: volrmmount.o
	${LINK.c} -o $@ volrmmount.o ${LDLIBS}
	$(POST_PROCESS)

catalog: $(POFILE)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

${VOLLIBDIR}/%: %
	${INS.file}

${VOLLIBDIR}:
	${INS.dir}

install: all ${VOLLIBDIR} ${VOLLIBPROG} ${ROOTBINPROG}

cstyle:
	${CSTYLE} ${SRCS}

lint:
	${LINT.c} eject.c -lvolmgt -ladm
	${LINT.c} volcancel.c -lvolmgt
	${LINT.c} volstat.c -lvolmgt
	${LINT.c} volmissing.c
	${LINT.c} volcheck.c -lvolmgt
	${LINT.c} volrmmount.c -lvolmgt

clean:
	${RM} ${OBJS} *.o a.out core

clobber: clean
	${RM} ${LPROG} $(BPROG)
