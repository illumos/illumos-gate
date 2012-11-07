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
# lib/librdc/Makefile.com

LIBRARY= librdc.a
VERS= .1

OBJECTS= netaddrs.o rdcerr.o rdcconfig.o rdc_ioctl.o rdcpersist.o rdcrules.o

# include library definitions
include ../../Makefile.lib

SRCS= ../common/*.c ../../../cmd/avs/rdc/rdc_ioctl.c 
SRCDIR= ../common

LIBS +=		$(DYNLIB) $(LINTLIB)

# definitions for lint

LINTFLAGS	+= -u -I.. -DDEBUG
LINTFLAGS	+= -erroff=E_FUNC_SET_NOT_USED
LINTFLAGS	+= -erroff=E_STATIC_UNUSED
LINTFLAGS	+= -erroff=E_SEC_PRINTF_VAR_FMT
LINTFLAGS	+= -erroff=E_SEC_SCANF_UNBOUNDED_COPY
LINTFLAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTFLAGS	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTFLAGS	+= -erroff=E_INCONS_VAL_TYPE_DECL2
LINTFLAGS	+= -erroff=E_BAD_FORMAT_ARG_TYPE2
LINTOUT=	lint.out
LINTOUT_INTER=	lintinter.out

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-address

LINTSRC=	$(LINTLIB:%.ln=%)
ROOTLINTDIR=	$(ROOTLIBDIR)
ROOTLINT=	$(LINTSRC:%=$(ROOTLINTDIR)/%)

CLEANFILES += 	$(LINTOUT) $(LINTLIB) $(LINTOUT_INTER) $(LINT_INTER)

CPPFLAGS +=	-DBUILD_REV_STR='"5.11"'
CFLAGS +=	-I..
CFLAGS64 +=	-I..
LDLIBS +=	-lsocket -lnsl -lnsctl -lc -lunistat -ldscfg

$(LINTLIB) :=	SRCS = ../common/llib-lrdc
$(LINTLIB) :=	LINTFLAGS = -nvx
$(LINTLIB) :=	LINTFLAGS64 = -nvx

$(LINT_INTER) :=	SRCS += ../common/llib-lrdc

.KEEP_STATE:

lint:		lintcheck $(LINTLIB)
lintinter:	$(LINT_INTER)

# include library targets
include ../../Makefile.targ

objs/%.o pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/rdc_ioctl.o pics/rdc_ioctl.o: ../../../cmd/avs/rdc/rdc_ioctl.c
	$(COMPILE.c) -o $@ ../../../cmd/avs/rdc/rdc_ioctl.c
	$(POST_PROCESS_O)

# install rule for lint library target
$(ROOTLINTDIR)/%:	../common/%
	$(INS.file)
