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
# Copyright 2026 Oxide Computer Company
#

PROGS = \
	v4mapped

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTSOCKOPT = $(ROOTOPTDIR)/sockopt
ROOTOPTPROGS = $(PROGS:%=$(ROOTOPTSOCKOPT)/%)

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

$(ROOTOPTPROGS): $(PROGS) $(ROOTOPTSOCKOPT)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTSOCKOPT): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTSOCKOPT)/%: %
	$(INS.file)

clobber: clean
	$(RM) $(PROGS)

FRC:
