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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#
#
# uts/common/idmap/Makefile
#
# include global definitions
include ../../../Makefile.master

IDMAP_PROT_DIR= 	$(SRC)/uts/common/rpcsvc

IDMAP_PROT_X=		$(IDMAP_PROT_DIR)/idmap_prot.x
DERIVED_SRCS=		idmap_xdr.c
DERIVED_FILES=		$(DERIVED_SRCS)
HDRS=			kidmap_priv.h
CHECKHDRS=		$(HDRS:%.h=%.check)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: all_h

all_h: $(DERIVED_FILES)


idmap_xdr.c:	$(IDMAP_PROT_X)
	$(RM) $@
	$(RPCGEN) -CMNc -DIDMAP_XDR_MAPPING_ONLY -o $@ $(IDMAP_PROT_X)

check:	$(CHECKHDRS)

clean:
	$(RM) $(DERIVED_FILES)

clobber:	clean
