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

SHFILES = sv sv.cluster
ROOTINIT_D = $(ROOTETC)/init.d

OWNER = root
GROUP = sys
FILEMODE = 0744

ROOTINIT_DPROG1 = $(ROOTINIT_D)/sv
ROOTINIT_DPROG2 = $(ROOTINIT_D)/sv.cluster

.KEEP_STATE:

all:	$(SHFILES)

install: all $(ROOTINIT_DPROG1) $(ROOTINIT_DPROG2) $(CLUSTERSBINDIR) \
	 $(CLUSTERLIBSTOPDIR) $(CLUSTERLIBSTARTDIR) $(ROOTLIBSVCMETHOD)
	-$(RM) $(CLUSTERLIBDSCFGSTOPDIR)/10sv
	-$(RM) $(CLUSTERLIBDSCFGSTARTDIR)/15sv
	-$(RM) $(CLUSTERSBINDIR)/sv
	-$(RM) $(ROOTLIBSVCMETHOD)/svc-sv
	-$(SYMLINK) ../../../sbin/sv $(CLUSTERLIBDSCFGSTOPDIR)/10sv
	-$(SYMLINK) ../../../sbin/sv $(CLUSTERLIBDSCFGSTARTDIR)/15sv
	$(LN) $(ROOTINIT_D)/sv $(ROOTLIBSVCMETHOD)/svc-sv
	$(CP) $(ROOTINIT_D)/sv.cluster $(CLUSTERSBINDIR)/sv

$(ROOTINIT_DPROG1): sv
	$(INS.file) sv

$(ROOTINIT_DPROG2): sv.cluster
	$(INS.file) sv.cluster

$(CLUSTERLIBSTOPDIR):
	$(INS.dir)

$(CLUSTERLIBSTARTDIR):
	$(INS.dir)

lint:

clean:
	$(RM) $(SHFILES)

clobber: clean
	$(RM) $(ROOTINIT_DPROG1) $(ROOTINIT_DPROG2)
