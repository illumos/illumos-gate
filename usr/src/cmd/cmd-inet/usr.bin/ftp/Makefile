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
# Copyright (c) 2018, Joyent, Inc.

PROG =		ftp
DEFAULTFILES =	ftp.dfl

OBJS =		cmds.o cmdtab.o ftp.o getpass.o glob.o main.o pclose.o \
		ruserpass.o domacro.o
AUTH_OBJS =	auth.o cmds_gss.o secure.o
OBJS +=		$(AUTH_OBJS)
SRCS =		$(OBJS:%.o=%.c)

include ../../../Makefile.cmd

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_FILE_OFFSET_BITS=64 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-address

# not linted
SMATCH=off

LDLIBS +=	-lsocket -lnsl -lgss

# ftp defines its own delete and glob - localize all symbols to prevent a
# name clash.
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

.KEEP_STATE:

all:		$(PROG) $(MAPFILE.NGB)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTPROG) $(ROOTETCDEFAULTFILES)

clean:
		$(RM) $(OBJS)

lint:		lint_SRCS

include ../../../Makefile.targ
