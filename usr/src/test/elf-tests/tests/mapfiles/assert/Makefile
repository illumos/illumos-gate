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

# Copyright 2019, Richard Lowe.

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG = test-assert

DATAFILES=				\
	mapfile.alias-with-others	\
	mapfile.circalias		\
	mapfile.guidance		\
	mapfile.no-extern		\
	mapfile.no-parent		\
	mapfile.not-alias		\
	mapfile.true			\
	mapfile.unknown-alias		\
	mapfile.unknown-assert		\
	mapfile.unknown-bind		\
	mapfile.unknown-shattr		\
	mapfile.unknown-type		\
	mapfile.wrongalias		\
	mapfile.wrongbits		\
	mapfile.wrongbits2		\
	mapfile.wrongscope		\
	mapfile.wrongsize		\
	mapfile.wrongtype		\
	mapfile.wrongtype-alias	\
	mapfile.wrongtype2		\
	object.c

ROOTOPTPKG = $(ROOT)/opt/elf-tests
TESTDIR = $(ROOTOPTPKG)/tests/mapfiles/assert

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

DATA = $(DATAFILES:%=$(TESTDIR)/%)
$(DATA) := FILEMODE = 0444

all: $(PROG)

install: all $(CMDS) $(DATA)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(CLEANFILES)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
