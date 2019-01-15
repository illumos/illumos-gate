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
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= lofiadm
OBJS= main.o utils.o
LZMAOBJS= LzmaEnc.o LzFind.o

SRCS= $(OBJS:%.o=%.c)

POFILES= $(OBJS:%.o=%.po)

include ../Makefile.cmd

CPPFLAGS += -I $(SRC)/common/crypto -I $(SRC)/common/lzma
LDLIBS += -ldevinfo -lpkcs11 -lcryptoutil

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

# not linted
SMATCH=off

LINTFLAGS += -erroff=E_NAME_USED_NOT_DEF2

.KEEP_STATE:

all: $(LZMAOBJS) $(PROG) $(POFILE)

LzmaEnc.o:	$(SRC)/common/lzma/LzmaEnc.c
	$(COMPILE.c) -o $@ $(SRC)/common/lzma/LzmaEnc.c
	$(POST_PROCESS)

LzFind.o:	$(SRC)/common/lzma/LzFind.c
	$(COMPILE.c) -o $@ $(SRC)/common/lzma/LzFind.c
	$(POST_PROCESS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LZMAOBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

clean:
	$(RM) $(PROG) $(OBJS) $(LZMAOBJS) $(POFILE) $(POFILES)

lint:	lint_SRCS

include ../Makefile.targ
