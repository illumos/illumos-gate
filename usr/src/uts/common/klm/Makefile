#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2012 by Delphix. All rights reserved.
#

include ../../../Makefile.master

NLM_PROT_X= ../rpcsvc/nlm_prot.x
SM_INTER_X= ../rpcsvc/sm_inter.x
NSM_ADDR_X= ../rpcsvc/nsm_addr.x

RPCGENFLAGS = -C -M -i 0
SED_INCL='/^.include/s:\.\..*/rpcsvc:rpcsvc:'

DERIVED_FILES= nlm_prot_clnt.c nlm_prot_xdr.c \
		sm_inter_clnt.c sm_inter_xdr.c \
		nsm_addr_clnt.c nsm_addr_xdr.c

install_h: all_h

all_h: $(DERIVED_FILES)

nlm_prot_clnt.c : $(NLM_PROT_X) nlm_prot_clnt.sed
	$(RPCGEN) $(RPCGENFLAGS) -l -o $@.tmp $(NLM_PROT_X)
	sed -f nlm_prot_clnt.sed < $@.tmp > $@
	$(RM) -f $@.tmp

nlm_prot_xdr.c : $(NLM_PROT_X)
	$(RPCGEN) $(RPCGENFLAGS) -c -o $@.tmp $(NLM_PROT_X)
	sed -e $(SED_INCL) < $@.tmp > $@
	$(RM) -f $@.tmp

sm_inter_clnt.c : $(SM_INTER_X) sm_inter_clnt.sed
	$(RPCGEN) $(RPCGENFLAGS) -l -o $@.tmp $(SM_INTER_X)
	sed -f sm_inter_clnt.sed < $@.tmp > $@
	$(RM) -f $@.tmp

sm_inter_xdr.c : $(SM_INTER_X)
	$(RPCGEN) $(RPCGENFLAGS) -c -o $@.tmp $(SM_INTER_X)
	sed -e $(SED_INCL) < $@.tmp > $@
	$(RM) -f $@.tmp

nsm_addr_clnt.c : $(NSM_ADDR_X) nsm_addr_clnt.sed
	$(RPCGEN) $(RPCGENFLAGS) -l -o $@.tmp $(NSM_ADDR_X)
	sed -f nsm_addr_clnt.sed < $@.tmp > $@
	$(RM) -f $@.tmp

nsm_addr_xdr.c : $(NSM_ADDR_X)
	$(RPCGEN) $(RPCGENFLAGS) -c -o $@.tmp $(NSM_ADDR_X)
	sed -e $(SED_INCL) < $@.tmp > $@
	$(RM) -f $@.tmp

check:

clean:
	$(RM) $(DERIVED_FILES)

clobber:	clean

.KEEP_STATE:
