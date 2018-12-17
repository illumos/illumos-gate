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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

include ../../Makefile.cmd

LIBADMDIR = ../../../lib/libadm/inc
CPPFLAGS += -I$(LIBADMDIR)
CFLAGS += $(CCVERBOSE)

PROG = devattr devreserv getvol putdgrp devfree getdev listdgrp getdgrp \
    putdev

LDLIBS += -ladm

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

SMOFF += signed

.KEEP_STATE:

.PARALLEL: $(PROG)

all: $(PROG)

clean:

install: all $(ROOTPROG)

lint: $(PROG:%=%.c)
	$(LINT.c) devattr.c	$(LDLIBS)
	$(LINT.c) devreserv.c	$(LDLIBS)
	$(LINT.c) getvol.c	$(LDLIBS)
	$(LINT.c) putdgrp.c	$(LDLIBS)
	$(LINT.c) devfree.c	$(LDLIBS)
	$(LINT.c) getdev.c	$(LDLIBS)
	$(LINT.c) listdgrp.c	$(LDLIBS)
	$(LINT.c) getdgrp.c	$(LDLIBS)
	$(LINT.c) putdev.c	$(LDLIBS)

FRC:
 
include ../../Makefile.targ
