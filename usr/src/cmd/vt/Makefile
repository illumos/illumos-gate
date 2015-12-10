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
# Copyright 2015 RackTop Systems.
#

PROG= vtdaemon vtinfo vtxlock

VTDAEMON_SRC= vtdaemon.c
VTINFO_SRC= vtinfo.c

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-uninitialized

vtdaemon := LDLIBS += -lpam -lbsm
lint_vtdaemon := LDLIBS += -lpam -lbsm

.KEEP_STATE:

all: $(PROG) 

vtdaemon: $(VTDAEMON_SRC)
	$(LINK.c) -o $@ $(VTDAEMON_SRC) $(LDLIBS)
	$(POST_PROCESS)

vtinfo: $(VTINFO_SRC)
	$(LINK.c) -o $@ $(VTINFO_SRC) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTLIBPROG)

clean:

lint: lint_vtdaemon lint_vtinfo

lint_vtdaemon:
	$(LINT.c) $(VTDAEMON_SRC) $(LDLIBS)

lint_vtinfo:
	$(LINT.c) $(VTINFO_SRC) $(LDLIBS)

include ../Makefile.targ
