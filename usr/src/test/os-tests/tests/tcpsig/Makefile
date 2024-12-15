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

PROGS = tcpsig
SCRIPTS = tcpsig_init tcpsig_fini

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTTCPSIG = $(ROOTOPTDIR)/tcpsig
ROOTOPTPROGS = $(PROGS:%=$(ROOTOPTTCPSIG)/%) \
	$(SCRIPTS:%=$(ROOTOPTTCPSIG)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CTF_MODE = link
LDLIBS += -lsocket
CPPFLAGS += -D_XOPEN_SOURCE=700 -D__EXTENSIONS__

.KEEP_STATE:

all: $(PROGS)

install: $(ROOTOPTPROGS)

clean:
	$(RM) *.o

$(ROOTOPTPROGS): $(PROGS) $(ROOTOPTTCPSIG)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTTCPSIG): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTTCPSIG)/%: %
	$(INS.file)

$(ROOTOPTTCPSIG)/%: %.ksh
	$(INS.rename)

clobber: clean
	$(RM) $(PROGS)

FRC:
