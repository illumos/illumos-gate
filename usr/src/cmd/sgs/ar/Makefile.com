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

PROG=		ar
XPG4PROG=	ar

include		$(SRC)/cmd/Makefile.cmd

COMOBJS=	main.o		file.o		cmd.o		global.o \
		message.o

POFILE=		../ar.po

OBJS=		$(COMOBJS:%=objs/%)
XPG4OBJS=	$(COMOBJS:%=objs.xpg4/%)

LLDFLAGS =	'-R$$ORIGIN/../../lib'
CPPFLAGS=	-I../../include $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)
C99MODE=	$(C99_ENABLE)

LDLIBS +=	-lelf
LINTFLAGS=	-mx
LINTFLAGS64=	-mx -m64

SED=		sed

$(XPG4) :=	CPPFLAGS += -DXPG4

SRCS=		$(COMOBJS:%.o=../common/%.c)
LINTSRCS=	$(SRCS)

CLEANFILES +=	$(OBJS) $(XPG4OBJS) $(LINTOUT)


# Building SUNWonld results in a call to the `package' target.  Requirements
# needed to run this application on older releases are established:
#	i18n support requires libintl.so.1 prior to 2.6

package :=	LDLIBS += /usr/lib/libintl.so.1
