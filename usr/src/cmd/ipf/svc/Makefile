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

PROG=		svc.ipfd
SRCS =          ipfd.c

MANIFEST=	ipfilter.xml
SVCMETHOD=	ipfilter

include $(SRC)/cmd/Makefile.cmd

LDLIBS +=       -lscf -lumem

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)
ROOTCMDDIR=		$(ROOT)/lib/svc/bin

all: $(PROG)

$(PROG): $(SRCS)
	$(LINK.c) -o $@ $(LDLIBS) $(SRCS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

clean:
	$(RM) $(PROG)

install:	all $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:		$(CHKMANIFEST)

include $(SRC)/cmd/Makefile.targ
