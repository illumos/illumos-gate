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
# cmd/bsmunconv/Makefile
#

PROG = bsmunconv

include ../Makefile.cmd

FILEMODE = 0740
DIRMODE = 0755

ROOTETCSECURITY =	$(ROOT)/etc/security
ROOTETCSECURITYSPOOL =	$(ROOT)/etc/security/spool
ROOTETCSECURITYFILES =  $(PROG:%=$(ROOTETCSECURITY)/%)

all: $(PROG)

install: all $(ROOTETCSECURITY) $(ROOTETCSECURITYFILES) $(ROOTETCSECURITYSPOOL)

$(ROOTETCSECURITY):
	$(INS.dir)

$(ROOTETCSECURITYSPOOL):
	$(INS.dir)

$(ROOTETCSECURITY)/%:%
	$(INS.file)

clean:

lint:

include ../Makefile.targ

.KEEP_STATE:
