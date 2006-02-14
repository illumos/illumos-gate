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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1991 by Sun Microsystems, Inc.
#
# cmd/aset/tasks/Makefile

PROG= cklist create_cklist eeprom env firewall sysconf tune usrgrp \
      firewall.restore sysconf.restore tune.restore usrgrp.restore

FILES= gpchk.awk pwchk.awk swchk.awk

include ../../Makefile.cmd

# we assume the Makefile above created ROOTDIR
ROOTDIR= $(ROOT)/usr/aset/tasks

ROOTPROG= $(PROG:%=$(ROOTDIR)/%)
ROOTFILES= $(FILES:%=$(ROOTDIR)/%)

DIRMODE= 700
FILEMODE= 700
OWNER= root

# install rule
$(ROOTDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all: $(PROG) $(FILES)

install: all $(ROOTPROG) $(ROOTFILES)

lint clean:

include ../../Makefile.targ
