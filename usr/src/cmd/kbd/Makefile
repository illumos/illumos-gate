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
#ident	"%Z%%M%	%I%	%E% SMI"
#

MANIFEST = keymap.xml
SVCMETHOD = keymap

include ../Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

.KEEP_STATE:

PROG	= kbd
CFLAGS	+= $(CCVERBOSE)
LDLIBS	+= -lcmd

DFLTD	= $(ROOTETC)/default
DDIRS	= $(DFLTD)

ETCDFLTPROG = $(PROG:%=$(DFLTD)/%)
$(ETCDFLTPROG) := FILEMODE = 0444
$(ETCDFLTPROG) := OWNER = root
$(ETCDFLTPROG) := GROUP = sys

$(ROOTMANIFEST) := FILEMODE = 0444

all: $(PROG) $(PROG).dfl

install: all $(DDIRS) $(ETCDFLTPROG) $(ROOTPROG) $(ROOTMANIFEST) \
	$(ROOTSVCMETHOD)

$(DDIRS):
	$(INS.dir)

$(DFLTD)/% : %.dfl
	$(INS.rename)

clean:
	$(RM) $(PROG)

lint:	lint_PROG

include ../Makefile.targ
