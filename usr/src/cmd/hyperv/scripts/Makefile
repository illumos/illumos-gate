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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

PROG=		hv_get_dhcp_info hv_get_dns_info
ALL=		$(PROG)

include		../../Makefile.cmd

all:	$(PROG)

LIBHYPERVPROG=	$(PROG:%=$(ROOTLIBHYPERV)/%)

install: all $(LIBHYPERVPROG)

lint:

clean:
	$(RM) $(PROG)

include ../../Makefile.targ
