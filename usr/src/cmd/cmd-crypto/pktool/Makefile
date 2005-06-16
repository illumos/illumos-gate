#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG =	pktool

OBJS =	pktool.o \
	common.o \
	derparse.o \
	osslcommon.o \
	p12common.o \
	setpin.o \
	list.o \
	delete.o \
	import.o \
	export.o \
	tokens.o

include ../../Makefile.cmd
include $(SRC)/lib/openssl/Makefile.openssl

SRCS =	$(OBJS:%.o=%.c)
POFILES = $(OBJS:%.o=%.po)
POFILE = $(PROG)_msg.po

CPPFLAGS += -I. $(OPENSSL_CPPFLAGS)
CFLAGS += $(CCVERBOSE)

DYNFLAGS += $(OPENSSL_DYNFLAGS)
LDFLAGS += $(OPENSSL_LDFLAGS)
LDLIBS += -lpkcs11 -lcryptoutil -lcrypto -lldap

LINTFLAGS += $(OPENSSL_LDFLAGS)

.KEEP_STATE:

all : $(PROG)

$(PROG) : $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(DYNFLAGS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE) : $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

install : all $(ROOTPROG)

clean :
	$(RM) $(OBJS)

lint : lint_SRCS

include ../../Makefile.targ

