#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Sample makefile to build the cache manager
#
SED=	sed

PROTOCOL_DIR=$(ROOT)/usr/include/rpcsvc

HDRS=

SRCS=cachemgr.c

OBJS=cachemgr.o nis_cache_svc.o nis_cache_xdr.o

PROG=nis_cachemgr

include $(SRC)/cmd/Makefile.cmd

LDLIBS += -lnsl

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

nis_cache.h: $(PROTOCOL_DIR)/nis_cache.x
	$(RPCGEN) -h $(PROTOCOL_DIR)/nis_cache.x |\
	$(SED) -e 's!\"$(PROTOCOL_DIR)/nis_cache.h\"!"nis_cache.h"!' > $@

nis_cache_svc.c: $(PROTOCOL_DIR)/nis_cache.x nis_clnt.h
	$(RPCGEN) -m $(PROTOCOL_DIR)/nis_cache.x |\
	$(SED) -e 's!\"$(PROTOCOL_DIR)/nis_cache.h\"!"nis_cache.h"!' > $@

nis_cache_xdr.c: $(PROTOCOL_DIR)/nis_cache.x nis_clnt.h
	$(RPCGEN) -c $(PROTOCOL_DIR)/nis_cache.x |\
	$(SED) -e 's!\"$(PROTOCOL_DIR)/nis_cache.h\"!"nis_cache.h"!' > $@

nis_clnt.h: $(PROTOCOL_DIR)/nis.x
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/nis.x |\
	$(SED) -n -e '/EDIT_START/,$$ p' |\
	$(SED) -e 's/_3_svc/_svc/' |\
	$(SED) -e 's/_3/_clnt/' > $@

nis_cachemgr: $(OBJS) nis_clnt.h
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c nis_cache.h nis_clnt.h
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)


include $(SRC)/cmd/Makefile.targ
