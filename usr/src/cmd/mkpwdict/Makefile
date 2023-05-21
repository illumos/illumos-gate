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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=	mkpwdict

include ../Makefile.cmd

CFLAGS += -I$(SRC)/lib/pam_modules/authtok_check

CERRWARN += -_gcc=-Wno-parentheses

CRACK_SRCDIR=	$(SRC)/lib/pam_modules/authtok_check/
CRACK_OBJS=	packer.o packlib.o dict.o stringlib.o

OBJS=	$(CRACK_OBJS) mkpwdict.o

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

%.o: $(CRACK_SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

mkpwdict: $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(PROG) $(OBJS)

include ../Makefile.targ
