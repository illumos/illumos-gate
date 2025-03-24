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
# Copyright 2025 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/mac
DATADIR = $(TESTDIR)/data

PROGS = \
	mac_cksum \
	mac_parsing

SCRIPTS = mac_ktest

DATAFILES = \
	ipv4_bad_proto.snoop \
	ipv4_icmp.snoop \
	ipv4_sctp.snoop \
	ipv4_tcp.snoop \
	ipv4_udp.snoop \
	ipv6_icmp.snoop \
	ipv6_sctp.snoop \
	ipv6_tcp.snoop \
	ipv6_udp.snoop \
	ipv6_eh_udp.snoop

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf
include $(SRC)/test/Makefile.com

CTF_MODE = link
LDLIBS += -lktest -lnvpair
CSTD= $(CSTD_GNU17)

CMDS = $(PROGS:%=$(TESTDIR)/%) \
	$(SCRIPTS:%=$(TESTDIR)/%)
TESTDATA = $(DATAFILES:%=$(DATADIR)/%)

$(CMDS) := FILEMODE = 0555
$(SCRIPTS) := FILEMODE = 0555
$(TESTDATA) := FILEMODE = 0444

all: $(PROGS)

install: all $(CMDS) $(TESTDATA)

lint:

clobber: clean
	-$(RM) $(PROGS)

clean:

$(CMDS): $(TESTDIR) $(PROGS)

$(TESTDIR):
	$(INS.dir)
$(DATADIR): $(TESTDIR)
	$(INS.dir)

$(TESTDATA): $(DATADIR)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)
