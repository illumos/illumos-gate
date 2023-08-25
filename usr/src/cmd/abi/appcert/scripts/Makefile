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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/abi/appcert/scripts/Makefile
#

PROG= appcert
APPCERT_SUBCMDS= symcheck symprof symreport abi_index
MODULES= AppcertUtil.pm

SCRIPTS= 	$(PROG) $(APPCERT_SUBCMDS)
MESSAGES=	$(SCRIPTS:%=%.po) $(MODULES:%.pm=%.po)


CLEANFILES=	$(SCRIPTS) $(MESSAGES)
CLOBBERFILES=	$(SCRIPTS) $(MESSAGES)

include $(SRC)/cmd/Makefile.cmd

ROOTLIBABIDIR   = $(ROOTLIB)/abi/appcert
ROOTLIBABIFILES = $(APPCERT_SUBCMDS:%=$(ROOTLIBABIDIR)/%)	\
		  $(MODULES:%=$(ROOTLIBABIDIR)/%)

.KEEP_STATE:

all: $(SCRIPTS) $(MODULES)

#
# install targets
#	Note: Makefile.cmd has a rule to cover $(ROOTSHFILES), but
# 	$(ROOTLIBABIFILES) are special install targets (go into
#	dirs not covered by Makefile.cmd), so we provide an explicit
#	rule for that.
#

install: all .WAIT $(ROOTPROG) $(ROOTLIBABIDIR) .WAIT $(ROOTLIBABIFILES)

_msg: $(MSGDOMAIN) $(MESSAGES)
	$(CP) $(MESSAGES) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

clean:
	-$(RM) $(CLEANFILES)

$(ROOTBINPROG): $(PROG)
	$(INS.file)

$(ROOTLIBABIDIR):
	$(INS.dir)

$(ROOTLIBABIDIR)/%: %
	$(INS.file)

lint:

clobber:	clean
	-$(RM) $(CLOBBERFILES)
