#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#cmd/ipf/examples/Makefile
#

SHPROG=		mkfilters
EXAMPLES=	BASIC.NAT BASIC_1.FW BASIC_2.FW \
		example.1 example.2 example.3 example.4 \
		example.5 example.6 example.7 example.8 \
		example.9 example.10 example.11 example.12 \
		example.13 example.sr firewall ftp-proxy \
		ftppxy ip_rules nat-setup nat.eg \
		pool.conf server tcpstate 

SHSRCS= $(SHPROG:%=%.sh)

include ../../Makefile.cmd

SHAREIPF= $(ROOT)/usr/share/ipfilter
SHAREIPFX= $(SHAREIPF)/examples

IPFEXAMPLES=	$(EXAMPLES:%=$(SHAREIPFX)/%)
IPFEXSHPROG=	$(SHPROG:%=$(SHAREIPFX)/%)

FILEMODE= 0644
OWNER= root
GROUP= bin

$(IPFEXSHPROG):=FILEMODE= 0755

$(SHAREIPFX)/% : % $(SHAREIPFX)
	$(INS.file)

$(SHAREIPF):
	$(INS.dir)

$(SHAREIPFX):
	$(INS.dir)

.KEEP_STATE:

all:		$(SHPROG)

clean:

clobber:

install:	all $(SHAREIPF) $(SHAREIPFX)  \
		$(IPFEXAMPLES) $(IPFEXSHPROG)

lint:

include ../../Makefile.targ

.PARALLEL:

