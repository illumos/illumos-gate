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
# cmd/ns/sdbc/etc/Makefile

include ../../../Makefile.cmd

INITPROGS = scm
BINPROGS = dscfg_reconfigure.cluster
SHFILES = $(INITPROGS) $(BINPROGS)
ROOTINIT_D = $(ROOTETC)/init.d

OWNER = root
GROUP = sys


ROOTBINPROGS= $(BINPROGS:%=$(ROOTBIN)/%)
ROOTINITPROGS= $(INITPROGS:%=$(ROOTINIT_D)/%)

# scm is mode 744, dscfg_reconfigure.cluster is mode 555
$(ROOTINITPROGS) := FILEMODE= 744
$(ROOTBINPROGS) := FILEMODE= 555

.KEEP_STATE:

all:	$(SHFILES) $(INITPROGS) $(BINPROGS)

install: $(ROOTBINPROGS) $(ROOTINITPROGS)

$(ROOTINIT_D)/%: %
	$(INS.file)

clean:
	$(RM) $(SHFILES)

clobber: clean
	$(RM) $(ROOTBINPROGS) $(ROOTINITPROGS)

lint:

FRC:
