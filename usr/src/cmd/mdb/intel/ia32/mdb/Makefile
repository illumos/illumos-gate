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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

SRCS =	kvm_ia32dep.c \
	kvm_isadep.c \
	mdb_ia32util.c \
	proc_x86util.c \
	proc_ia32dep.c

%.o: ../../mdb/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.ln: ../../mdb/%.c
	$(LINT.c) -c $<

include ../../../../Makefile.cmd
include ../../Makefile.ia32
include ../../../Makefile.mdb

CPPFLAGS += -I../../mdb

install: all $(ISAEXEC) $(ROOTPROG32) $(ROOTLINK32)
	-$(RM) $(ROOTPROG)
	-$(LN) $(ISAEXEC) $(ROOTPROG)
	-$(RM) $(ROOTLINK)
	-$(LN) $(ISAEXEC) $(ROOTLINK)
