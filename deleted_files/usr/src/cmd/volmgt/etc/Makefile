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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for volume management files that go in /etc and /var/svc
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/volmgt/etc/Makefile

MANIFEST = 	volfs.xml
SVCMETHOD =	svc-volfs

include ../../Makefile.cmd

ETCFILES=	vold.conf rmmount.conf

ROOTETCFILES=	$(ETCFILES:%=$(ROOTETC)/%)

#
# For some reason I have to set these modes explicitly otherwise
# they end up executable.
#
$(ROOTETC)/vold.conf := FILEMODE = 0444
$(ROOTETC)/rmmount.conf := FILEMODE = 0444
$(ROOTETC)/vold.conf := OWNER = root
$(ROOTETC)/rmmount.conf := OWNER = root

ROOTMANIFESTDIR = 	$(ROOTSVCSYSTEMFILESYSTEM)

.KEEP_STATE:

all: $(ETCFILES)

lint:

cstyle:

install: all $(ROOTETCFILES) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check: $(CHKMANIFEST)

clean:     

clobber: clean

include ../../Makefile.targ
