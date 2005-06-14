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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#


include ../../../Makefile.cmd

ETCNFS= $(ROOTETC)/nfs
VARNFS= $(ROOT)/var/nfs
DEFNFS= $(ROOT)/default
TXTS= nfssec.conf
NFSTXTS= nfslog.conf
DEFTXTS= nfs
V4SSDIR= $(VARNFS)/v4_state $(VARNFS)/v4_oldstate

IETCFILES=			$(TXTS:%=$(ROOTETC)/%)
INFSETCFILES=			$(NFSTXTS:%=$(ROOTETC)/nfs/%)
IDEFFILES=			$(DEFTXTS:%=$(ROOTETC)/default/%)

$(VARNFS) := GROUP = bin
FILEMODE= 0644
OWNER= root
GROUP= sys

$(V4SSDIR) := GROUP = daemon 
$(V4SSDIR) := OWNER = daemon 

all: $(TXTS) $(NFSTXTS) $(DEFTXTS)

install: all $(IETCFILES) $(ETCNFS) $(INFSETCFILES) $(VARNFS) $(V4SSDIR) $(IDEFFILES)

$(ROOTETC)/%: %
	$(INS.file)

$(ROOTETC)/nfs/%: %
	$(INS.file)

$(ETCNFS):
	$(INS.dir)

$(VARNFS):
	$(INS.dir)

$(V4SSDIR):
	$(INS.dir)

$(ROOTETC)/default/%: %
	$(INS.file)

.KEEP_STATE:

FRC:

clean clobber lint:
