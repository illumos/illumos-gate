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
# cmd/dodatadm/Makefile

SCRIPT =	dodatadm.udaplt

include $(SRC)/cmd/Makefile.cmd

STARTDATADM= $(ROOTETC)/rc2.d/S81dodatadm.udaplt

INITD= $(ROOTETC)/init.d
RC2D= $(ROOTETC)/rc2.d
DIRS= $(INITD) $(RC2D)

FILEMODE= 0744

ETCINITPROG=	$(SCRIPT:%=$(INITD)/%)

.KEEP_STATE:

all: $(SCRIPT)

install: all $(DIRS) $(ETCINITPROG) ln_PROG

$(INITD)/% : % $(INITD)
	$(INS.file)

$(DIRS):
	$(INS.dir)

ln_PROG : $(ETCINITPROG)
	-$(RM) $(STARTDATADM)
	$(LN) $(INITD)/$(SCRIPT) $(STARTDATADM)

clean:

lint:

include $(SRC)/cmd/Makefile.targ
