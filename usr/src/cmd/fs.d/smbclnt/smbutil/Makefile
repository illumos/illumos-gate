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

#
# cmd/fs.d/smbclnt/smbutil/Makefile
#

PROG=		smbutil

include		$(SRC)/cmd/Makefile.cmd

OBJS=   smbutil.o login.o lookup.o print.o status.o view.o

SRCS=	$(OBJS:%.o=%.c)
POFILE=	smbutil_all.po
POFILES= $(OBJS:%.o=%.po)
CLOBBERFILES+=  $(POFILE) $(POFILES)

CSTD= $(CSTD_GNU99)

LDLIBS += -lsmbfs -lnsl

CPPFLAGS += -I$(SRC)/lib/libsmbfs \
	-I$(SRC)/uts/common/smbclnt -I$(SRC)/uts/common

# Debugging
${NOT_RELEASE_BUILD} CPPFLAGS += -DDEBUG

# uncomment these for dbx debugging
#COPTFLAG = -g
#CTF_FLAGS =
#CTFCONVERT_O=
#CTFMERGE_LIB=

# disable some of the less important lint
LINTFLAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTFLAGS	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2

all:		$(PROG)

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install:	all $(ROOTPROG)

$(ROOTPROG):	$(PROG)
	$(INS.file) $(PROG)

catalog: $(POFILE)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

lint:	lint_SRCS

clean :
	$(RM) $(OBJS)

.KEEP_STATE:

include ../../../Makefile.targ
