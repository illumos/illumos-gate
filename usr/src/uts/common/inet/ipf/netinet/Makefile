#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2019 Joyent, Inc.
#
# uts/common/inet/ipf/netinet/Makefile
#
# include global definitions
include ../../../../../Makefile.master

HDRS=	ipl.h ip_compat.h ip_fil.h ip_nat.h ip_proxy.h ip_state.h ip_frag.h \
	ip_auth.h ip_lookup.h ip_pool.h ip_htable.h ipf_stack.h ipf_cfw.h

ROOTDIRS= $(ROOT)/usr/include/netinet

ROOTHDRS= $(HDRS:%=$(ROOT)/usr/include/netinet/%)

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIRS)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIRS) $(ROOTHDRS)

$(ROOTDIRS):
	$(INS.dir)

check:
