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
# Copyright 2015 Gary Mills
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include  ../../Makefile.master

# Relative path to ensure path to header file is also relative
HEAD_DIR= ../../head/rpcsvc
UTS_DIR= ../../uts/common/rpcsvc
RPC_DIR= ../../uts/common/rpc

SUBDIRS=	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

DERIVED_FILES=  \
	common/bootparam_prot_xdr.c	\
	common/rstat_xdr.c	\
	common/rusers_xdr.c	\
	common/spray_xdr.c	\
	common/nlm_prot.c	\
	common/sm_inter_xdr.c	\
	common/mount_xdr.c	\
	common/nsm_addr_xdr.c	\
	common/rpc_sztypes.c

CLEANFILES += $(DERIVED_FILES)

# include library definitions
include ../Makefile.lib

# definitions for install_h target
HDRS= 		$(TXTS)
ROOTHDRDIR=	$(ROOT)/usr/include/rpcsvc
ROOTHDRS=	$(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=	$(HDRS:%.h=%.check)

# install rule for install_h target
$(ROOTHDRDIR)/%: %
	$(INS.file)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all:	$(DERIVED_FILES) $(TXTS) .WAIT $(SUBDIRS)

install: all .WAIT $(SUBDIRS)

install_h: $(DERIVED_FILES) $(ROOTHDRS)

check: $(CHECKHDRS)

clean clobber lint: $(SUBDIRS)

#
# Rules for building the derived files
#
# Derived files
#
common/bootparam_prot_xdr.c: $(HEAD_DIR)/bootparam_prot.x
	$(RPCGEN) -c $(HEAD_DIR)/bootparam_prot.x > $@

common/rstat_xdr.c: $(HEAD_DIR)/rstat.x
	$(RPCGEN) -c $(HEAD_DIR)/rstat.x > $@

common/rusers_xdr.c: $(HEAD_DIR)/rusers.x
	$(RPCGEN) -c $(HEAD_DIR)/rusers.x > $@

common/sm_inter_xdr.c: $(UTS_DIR)/sm_inter.x
	$(RPCGEN) -c $(UTS_DIR)/sm_inter.x > $@

common/spray_xdr.c: $(HEAD_DIR)/spray.x
	$(RPCGEN) -c $(HEAD_DIR)/spray.x > $@

common/nlm_prot.c: $(UTS_DIR)/nlm_prot.x
	$(RPCGEN) -c $(UTS_DIR)/nlm_prot.x > $@

common/mount_xdr.c: $(HEAD_DIR)/mount.x
	$(RPCGEN) -c $(HEAD_DIR)/mount.x > $@

common/nsm_addr_xdr.c: $(UTS_DIR)/nsm_addr.x
	$(RPCGEN) -c $(UTS_DIR)/nsm_addr.x > $@

common/rpc_sztypes.c: $(RPC_DIR)/rpc_sztypes.x
	$(RPCGEN) -c $(RPC_DIR)/rpc_sztypes.x > $@

# include library targets
include ../Makefile.targ

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
