#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# uts/common/inet/ipf/netinet/Makefile
#
# include global definitions
include ../../../../../Makefile.master

HDRS=	ipl.h ip_compat.h ip_fil.h ip_icmp.h ip_nat.h ip_proxy.h ip_state.h

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

check:	$(CHECKHDRS)
