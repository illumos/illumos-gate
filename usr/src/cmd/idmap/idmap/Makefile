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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

PROG =		idmap
CLIENTOBJS =	idmap.o idmap_engine.o namemaps.o
# idmap_clnt.o
CLIENTSRCS =	$(CLIENTOBJS:%.o=%.c)
POFILES = 	$(CLIENTOBJS:.o=.po)
OBJS =		$(CLIENTOBJS)
SRCS =		$(CLIENTSRCS)
IDMAP_PROT_DIR =        $(SRC)/head/rpcsvc

include ../../Makefile.cmd

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-address

# not linted
SMATCH=off

POFILE = 	$(PROG)_all.po
LDLIBS +=	-lidmap -ladutils -lsldap -lldap
FILEMODE =	0555

INCS += -I. \
	-I../../../lib/libidmap/common \
	-I../../../lib/libadutils/common \
	-I../../../lib/libsldap/common \
	-I$(IDMAP_PROT_DIR)

CFLAGS += $(CCVERBOSE)
$(OBJS) :=	CPPFLAGS += $(INCS) -D_REENTRANT
$(POFILE) :=	CPPFLAGS += $(INCS)

lint_SRCS :=	CPPFLAGS += $(INCS)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -g -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

LINTFLAGS += -erroff=E_NAME_DEF_NOT_USED2

include ../../Makefile.targ


