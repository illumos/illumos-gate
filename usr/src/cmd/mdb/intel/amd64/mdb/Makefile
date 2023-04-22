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
# Copyright 2019 Joyent, Inc.
#

SRCS =	kvm_amd64dep.c \
	kvm_isadep.c \
	mdb_amd64util.c \
	mdb_ia32util.c \
	mdb_x86util.c \
	mdb_bhyve.c \
	proc_x86util.c \
	proc_amd64dep.c

%.o: %.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.o: ../../mdb/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.ln: %.c
	$(LINT.c) -c $<

%.ln: ../../mdb/%.c
	$(LINT.c) -c $<

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/mdb/intel/Makefile.amd64
include $(SRC)/cmd/mdb/Makefile.mdb
include $(SRC)/Makefile.psm

CPPFLAGS += -I../../mdb

LDLIBS += -lsaveargs -lvmm

install: all $(ISAEXEC) $(ROOTPROG64) $(ROOTLINK64)
