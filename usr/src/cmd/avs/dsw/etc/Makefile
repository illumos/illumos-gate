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

include ../../../Makefile.cmd
include ../../Makefile.com


SHFILES = ii ii.cluster
ROOTINIT_D = $(ROOTETC)/init.d
USRTOOL_D = $(ROOTUSRTOOLS)

OWNER = root
GROUP = sys
FILEMODE = 0744

ROOTINIT_DPROG = $(ROOTINIT_D)/ii
ROOTINIT_DPROG2= $(ROOTINIT_D)/ii.cluster

.KEEP_STATE:

all:	$(SHFILES)

install:  $(ROOTINIT_DPROG) $(ROOTINIT_DPROG2) $(CLUSTERSBINDIR) $(ROOTLIBSVCMETHOD)
	-$(RM) $(CLUSTERLIBDSCFGSTOPDIR)/20ii
	-$(RM) $(CLUSTERLIBDSCFGSTARTDIR)/05ii
	-$(RM) $(CLUSTERSBINDIR)/ii
	-$(RM) $(ROOTLIBSVCMETHOD)/svc-ii
	-$(SYMLINK) ../../../sbin/ii $(CLUSTERLIBDSCFGSTOPDIR)/20ii
	-$(SYMLINK) ../../../sbin/ii $(CLUSTERLIBDSCFGSTARTDIR)/05ii
	$(LN) $(ROOTINIT_D)/ii $(ROOTLIBSVCMETHOD)/svc-ii
	$(LN) $(ROOTINIT_D)/ii.cluster $(CLUSTERSBINDIR)/ii

$(ROOTINIT_DPROG): ii
	$(INS.file) ii

$(ROOTINIT_DPROG2): ii.cluster
	$(INS.file) ii.cluster

clean:
	$(RM) $(SHFILES)

clobber: clean

lint:
