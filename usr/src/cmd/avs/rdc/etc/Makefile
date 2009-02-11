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

PROG1 = rdc
PROG2 = rdcfinish
PROG3 = rdc.cluster
SHFILES = $(PROG1) $(PROG2) $(PROG3)
ROOTINIT_D = $(ROOTETC)/init.d

OWNER = root
GROUP = sys
FILEMODE = 0744

ROOTETCFILES= $(ETCFILES:%=$(ROOTETC)/%)

ROOTINIT_DPROG1 = $(ROOTINIT_D)/$(PROG1)
ROOTINIT_DPROG2 = $(ROOTINIT_D)/$(PROG2)
ROOTINIT_DPROG3 = $(ROOTINIT_D)/$(PROG3)

.KEEP_STATE:

all:	$(SHFILES) $(ETCFILES) $(INITFILES)

install: $(ROOTINIT_DPROG1) $(ROOTINIT_DPROG2) $(ROOTINIT_DPROG3) $(ROOTLIBSVCMETHOD) $(CLUSTERSBINDIR)
	-$(RM) $(CLUSTERLIBDSCFGSTOPDIR)/15rdc
	-$(RM) $(CLUSTERLIBDSCFGSTARTDIR)/10rdc
	-$(RM) $(ROOTLIBSVCMETHOD)/svc-rdc
	-$(RM) $(ROOTLIBSVCMETHOD)/svc-rdcsyncd
	-$(RM) $(CLUSTERSBINDIR)/rdc
	-$(SYMLINK) ../../../sbin/rdc $(CLUSTERLIBDSCFGSTOPDIR)/15rdc
	-$(SYMLINK) ../../../sbin/rdc $(CLUSTERLIBDSCFGSTARTDIR)/10rdc
	$(LN) $(ROOTINIT_D)/rdc $(ROOTLIBSVCMETHOD)/svc-rdc
	$(LN) $(ROOTINIT_D)/rdcfinish $(ROOTLIBSVCMETHOD)/svc-rdcsyncd
	$(CP) $(ROOTINIT_D)/rdc.cluster $(CLUSTERSBINDIR)/rdc

$(ROOTINIT_DPROG1): $(PROG1)
	$(INS.file) $(PROG1)

$(ROOTINIT_DPROG2): $(PROG2)
	$(INS.file) $(PROG2)

$(ROOTINIT_DPROG3): $(PROG3)
	$(INS.file) $(PROG3)

clean:
	$(RM) $(SHFILES)

clobber: clean

lint:
