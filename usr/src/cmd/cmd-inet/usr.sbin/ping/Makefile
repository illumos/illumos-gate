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

PROG=		ping
OBJS=		ping.o ping_aux.o ping_aux6.o
SRCS=		$(OBJS:.o=.c)

include	../../../Makefile.cmd

$(ROOTUSRSBIN)/ping	:=	FILEMODE= 04555

# Ping uses the ancillary data feature which is available only through
# UNIX 98 standards version of Socket interface. This interface is supposed to
# be accessed by -lxnet. In addition -lsocket and is used to
# capture new not-yet-standard interfaces. Someday -lxnet alone should be enough
# when IPv6 inspired new interfaces are part of standards.
LDLIBS +=	-lxnet -lsocket -lm -linetutil

# These #defines are required to use SUSv3 interfaces
CPPFLAGS += -D_XOPEN_SOURCE=600 -D__EXTENSIONS__

CSTD=	$(CSTD_GNU99)

# Setting the above defines to use the UNIX98 ancillary data feature
# causes lint to output warnings about lint library declarations conflicting
# with those in the header files. Since we need these features the best
# course of action is to switch the types of the resulting warnings off
# when running lint.
LINTFLAGS += -erroff=E_INCONS_VAL_TYPE_DECL2 -erroff=E_INCONS_ARG_DECL2 \
		-erroff=E_NAME_USED_NOT_DEF2

.KEEP_STATE:
.PARALLEL:

all:	$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../../Makefile.targ
