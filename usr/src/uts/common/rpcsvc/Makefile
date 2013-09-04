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
# Copyright (c) 2012 by Delphix. All rights reserved.
#
# uts/common/rpcsvc/Makefile
#	This makefile installs system header files that go into
#	/usr/include/rpcsvc.
#
# include global definitions
include ../../../Makefile.master

# Protocol descriptions.  Alas, the NFS protocol cannot be expressed
# completely via rpcgen.  The NLM description should go here some day.
# Also, the v3 headers have been hacked so that they no longer
# quite reflect what goes over the wire.
IDMAP_PROT_X=	idmap_prot.x
RPCGEN_SRC=	autofs_prot.x nlm_prot.x sm_inter.x nsm_addr.x \
		$(IDMAP_PROT_X)

DERIVED_HDRS=	$(RPCGEN_SRC:%.x=%.h)

ALLHDRS=	$(RPCGEN_SRC) $(DERIVED_HDRS)

ROOTDIRS=	$(ROOT)/usr/include/rpcsvc

ROOTHDRS=	$(ALLHDRS:%=$(ROOTDIRS)/%)

RPCGENFLAGS = -C
idmap_prot.h :=	RPCGENFLAGS += -MN
nlm_prot.h :=	RPCGENFLAGS += -M
sm_inter.h :=	RPCGENFLAGS += -M
nsm_addr.h :=	RPCGENFLAGS += -M

$(ROOTDIRS)/%: %
	$(INS.file)

.KEEP_STATE:

# all_h permits derived headers to be built here in the uts source area
# for the kernel to reference, without going so far as to install them.
#
all_h: $(DERIVED_HDRS)

install_h: all_h $(ROOTDIRS) $(ROOTHDRS)

clean:
	$(RM) $(DERIVED_HDRS)

clobber: clean

# Don't check rpcgen-derived files.
check:

$(ROOTDIRS):
	$(INS.dir)

%.h: %.x
	$(RPCGEN) $(RPCGENFLAGS) -h $< -o $@
