#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2022 Tintri by DDN, Inc. All rights reserved.
#

LIBPROG = rpcsec_gss_conn

SNOOPDIR = $(SRC)/cmd/cmd-inet/usr.sbin/snoop
SNOOPOBJS = nfs4_xdr.o

OBJS = $(LIBPROG:%=%.o) $(SNOOPOBJS)

%.o: $(SNOOPDIR)/%.c
	$(COMPILE.c) -o $@ $< -I$(SNOOPDIR)
	$(POST_PROCESS_O)

include ../Makefile.com

CERRWARN += -_gcc=-Wno-switch
LDLIBS += -lnsl -lgss
