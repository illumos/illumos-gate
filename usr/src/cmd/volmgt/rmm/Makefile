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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for Removable Media Mounter.
#
# cmd/volmgt/rmm/Makefile
#

PROG=	rmmount


include ../../../lib/Makefile.lib
include ../../Makefile.cmd
include ../Makefile.volmgt

SED=	sed

OBJS=	rmm.o rmm_util.o rmm_config.o
SRCS=	$(OBJS:%.o=%.c) ${ACTS:%.so.$(ACT_VERS)=%.c}

# identification functions are in src/cmd/fs.d/<fstype>.
IDENT_VERS=1

# actions
ACT_VERS=1
ACTSVOL=	action_workman.so.${ACT_VERS} action_dvdvideo.so.${ACT_VERS}
ACTS=		$(ACTSVOL) action_filemgr.so.${ACT_VERS}

CFLAGS += $(CCVERBOSE) -D_FILE_OFFSET_BITS=64

CPPFLAGS += 	-DACT_VERS=${ACT_VERS} -DIDENT_VERS=${IDENT_VERS}

$(PROG) :=	LDLIBS += -lvolmgt -ladm -lcontract
$(ACTSVOL) :=	LDLIBS += -lvolmgt
$(ACTS) :=	LDLIBS += -lc

# to get the correct DSO flags used for compilation/linking
# (should also use "-zdefs" for DYNFLAGS, but ACTS are not yet self-contained)
$(ACTS) :=	CFLAGS += $(C_PICFLAGS)
$(ACTS) :=	HSONAME =
$(ACTS) :=	ZDEFS =

# for messaging catalog
#
POFILE= rmm.po

#
# Rules for making shared objects out of .c files.  Works well if
# we have a one-to-one mapping.  Applies in all cases so far.
#
.SUFFIXES: .so.${ACT_VERS} ${SUFFIXES}

.c.so.${ACT_VERS}:
	${CC} ${CPPFLAGS} ${CFLAGS} $(GSHARED) -o $@ $< $(DYNFLAGS) $(LDLIBS)
	$(POST_PROCESS_SO)

# install macros and rule
#
ROOTUSRSBINPROG=	${PROG:%=${ROOTUSRSBIN}/%}
RMMLIBOBJS=		${ACTS:%=${RMMLIBDIR}/%}

lint :=	LINTFLAGS += -errchk=longptr64

${RMMLIBDIR}/%: %
	${INS.file}

.KEEP_STATE:

all: ${PROG} ${ACTS}

catalog: $(POFILE)

$(POFILE): $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS) | \
	$(XGETTEXT) $(XGETFLAGS) -
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

${PROG}: ${OBJS}
	${LINK.c} -o $@ ${OBJS} $(LDLIBS)
	$(POST_PROCESS)

lint:
	$(LINT.c) ${SRCS}

cstyle:
	${CSTYLE} ${SRCS}

install: all ${RMMLIBDIR} ${RMMLIBOBJS} ${ROOTUSRSBINPROG}

${RMMLIBDIR}:
	${INS.dir}

clean: 
	${RM} $(OBJS) ${ACTS} core a.out

clobber: clean
	${RM} $(PROG)
