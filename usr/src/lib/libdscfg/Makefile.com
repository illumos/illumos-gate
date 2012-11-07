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

LIBRARY= libdscfg.a
VERS= .1

OBJECTS= \
	cfg.o \
	cfg_cluster.o \
	cfg_local.o \
	cfg_lockdlck.o \
	cfg_lockdmsg.o \
	cfg_vols.o


# include library definitions
include ../../Makefile.lib

SRCDIR=	../common
SRCS=		$(OBJECTS:%.o=../common/%.c)

LIBS +=		$(DYNLIB) $(LINTLIB)

# definitions for lint

LINTFLAGS +=	-u
LINTFLAGS += -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTFLAGS += -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTFLAGS += -erroff=E_FUNC_SET_NOT_USED
LINTFLAGS += -erroff=E_SEC_SCANF_UNBOUNDED_COPY
LINTFLAGS += -erroff=E_BAD_FORMAT_ARG_TYPE2
LINTOUT=	lint.out
LINTOUT_INTER=	lintinter.out

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-address

ROOTLINTDIR=	$(ROOTLIBDIR)
ROOTLINT=	$(LINTSRC:%=$(ROOTLINTDIR)/%)

CLEANFILES += 	$(LINTOUT) $(LINTOUT_INTER) $(LINT_INTER)

LDLIBS +=	-lnsctl -lunistat -ladm -lsocket -lnsl -lc

.KEEP_STATE:

lint: lintcheck

# include library targets
include ../../Makefile.targ
