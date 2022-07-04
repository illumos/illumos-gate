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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2022 Garrett D'Amore
#
# cmd/cmd-inet/etc/init.d/Makefile

PPPD=	pppd
PROG=	$(PPPD)

include ../../../Makefile.cmd

PPPDK=	K50pppd
PPPDS=	S47pppd

INITD= $(ROOTETC)/init.d
DIRS= $(INITD) $(ROOTETC)/rc0.d $(ROOTETC)/rcS.d $(ROOTETC)/rc1.d \
	$(ROOTETC)/rc2.d $(ROOTETC)/rc3.d
FILEMODE= 0744

ETCINITPROG=	$(PROG:%=$(INITD)/%)

.KEEP_STATE:

all: $(PROG)

install: all $(DIRS) $(ETCINITPROG) $(ETCDFLTPROG) ln_PROG

$(INITD)/% : % $(INITD)
	$(INS.file)

ln_PROG : $(ETCINITPROG)
	-$(RM) $(ROOTETC)/rc0.d/$(PPPDK)
	$(LN) $(INITD)/$(PPPD) $(ROOTETC)/rc0.d/$(PPPDK)
	-$(RM) $(ROOTETC)/rc1.d/$(PPPDK)
	$(LN) $(INITD)/$(PPPD) $(ROOTETC)/rc1.d/$(PPPDK)
	-$(RM) $(ROOTETC)/rcS.d/$(PPPDK)
	$(LN) $(INITD)/$(PPPD) $(ROOTETC)/rcS.d/$(PPPDK)
	-$(RM) $(ROOTETC)/rc2.d/$(PPPDS)
	$(LN) $(INITD)/$(PPPD) $(ROOTETC)/rc2.d/$(PPPDS)

$(DIRS):
	$(INS.dir)

clean:

lint:

include ../../../Makefile.targ

.PARALLEL:
