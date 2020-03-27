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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

MANIFEST=	dscp.xml
SVCMETHOD=	svc-dscp

include ../../../cmd/Makefile.cmd

.KEEP_STATE:

# definitions for installing the manifest
ROOTMANIFESTDIR	=	$(ROOTSVCPLATFORMSUN4U)

# definitions for installing the PPP options
OPTIONS =		dscp.ppp.options
ROOTOPTIONSDIR =	$(ROOT)/usr/platform/SUNW,SPARC-Enterprise/lib
ROOTOPTIONS =		$(OPTIONS:%=$(ROOTOPTIONSDIR)/%)

$(ROOTOPTIONSDIR):
	$(INS.dir)

$(ROOTOPTIONSDIR)/%: %
	$(INS.file)

all clean clobber:

install: $(ROOTMANIFEST) $(ROOTSVCMETHOD) $(ROOTOPTIONS)

check: $(CHKMANIFEST)

include ../../../cmd/Makefile.targ
