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

PROG=		in.ndpd
OBJS=		config.o main.o ndp.o tables.o trace.o
SRCS=		$(OBJS:%.o=%.c)
SVCMETHOD=	svc-ndp
MANIFEST=	ndp.xml

include		../../../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKROUTING)

# in.ndpd uses the ancillary data feature which is available only through
# UNIX 98 standards version of Socket interface. This interface is supposed to
# be accessed by -lxnet. In addition -lsocket is used to
# capture new not-yet-standard interfaces. Someday -lxnet alone should be enough
# when IPv6 inspired new interfaces are part of standards.
LDLIBS +=	-ldhcpagent -lxnet -lsocket -lipadm

# these #defines are required to use UNIX 98 interfaces
_D_UNIX98_EXTN= -D_XOPEN_SOURCE=500 -D__EXTENSIONS__

$(OBJS)		:= CPPFLAGS +=  $(_D_UNIX98_EXTN)

LINTFLAGS +=	$(_D_UNIX98_EXTN)

# This shouldn't be necessary, but linking with libxnet requires it.
LINTFLAGS +=	-erroff=E_INCONS_ARG_DECL2 -erroff=E_INCONS_VAL_TYPE_DECL2

# This is needed to avoid littering the code with useless LINTED statements
# for each place where pointers are casted.  It's not perfect, but being
# perfect would require a bigger rewrite.
LINTFLAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN

CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-uninitialized

CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
$(OBJS) := CFLAGS += $(CTF_FLAGS)

.KEEP_STATE:

.PARALLEL:  $(OBJS)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

include		../Makefile.lib

install: all $(ROOTLIBINETPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include		../../../Makefile.targ
