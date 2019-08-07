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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG =		ifconfig
ROOTFS_PROG =	$(PROG)
LOCALOBJS=	ifconfig.o revarp.o
COMMONOBJS=	compat.o
OBJS=		$(LOCALOBJS) $(COMMONOBJS)

include ../../../Makefile.cmd
include ../../Makefile.cmd-inet

LOCALSRCS=	$(LOCALOBJS:%.o=%.c)
COMMONSRCS=	$(CMDINETCOMMONDIR)/$(COMMONOBJS:%.o=%.c)
SRCS=		$(LOCALSRCS) $(COMMONSRCS)

CPPFLAGS +=	-I$(CMDINETCOMMONDIR) -I$(SRC)/common/net/dhcp
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-parentheses
LDLIBS +=       -ldhcpagent -ldlpi -linetutil -lipmp -ldladm -lipadm
LINTFLAGS +=	-m

ROOTUSRSBINLINKS = $(PROG:%=$(ROOTUSRSBIN)/%)

# ifconfig uses the ancillary data feature which is available only through
# UNIX 98 standards version of Socket interface. This interface is supposed to
# be accessed by -lxnet. In addition -lsocket and -lnsl are used to
# capture new not-yet-standard interfaces. Someday -lxnet alone should be
# enough when IPv6 inspired new interfaces are part of standards.
LDLIBS +=	-lxnet -lsocket -lnsl

# these #defines are required to use UNIX 98 interfaces
_D_UNIX98_EXTN= -D_XOPEN_SOURCE=500 -D__EXTENSIONS__

$(OBJS)		:= CPPFLAGS +=	$(_D_UNIX98_EXTN)

LINTFLAGS +=	$(_D_UNIX98_EXTN)

.KEEP_STATE:

all:	$(ROOTFS_PROG)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install:	all $(ROOTSBINPROG) $(ROOTUSRSBINLINKS)

$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../../Makefile.targ
