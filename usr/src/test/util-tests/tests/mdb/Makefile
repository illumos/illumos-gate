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
# Copyright 2020 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/mdb

PROG = mdbtest

ROOTPROG = $(PROG:%=$(TESTDIR)/%)

MAKEDIRS = \
	exit-e \
	format \
	options \
	typedef

FILES = \
	exit-e/err.cmdbadopt.ksh \
	exit-e/err.enocmd.ksh \
	exit-e/err.nowrite.ksh \
	exit-e/err.unmapped.ksh \
	exit-e/tst.output.ksh \
	exit-e/tst.output.ksh.out \
	exit-e/tst.simple.ksh \
	format/tst.format-cap-E.mdb \
	format/tst.format-cap-E.mdb.out \
	format/tst.format-cap-G.mdb \
	format/tst.format-cap-G.mdb.out \
	format/tst.format-cap-J.mdb \
	format/tst.format-cap-J.mdb.out \
	format/tst.format-cap-P.mdb \
	format/tst.format-cap-P.mdb.out \
	format/tst.format-cap-R.mdb \
	format/tst.format-cap-R.mdb.out \
	format/tst.format-e.mdb \
	format/tst.format-e.mdb.out \
	format/tst.format-g.mdb \
	format/tst.format-g.mdb.out \
	format/tst.format-j.mdb \
	format/tst.format-j.mdb.out \
	format/tst.format-p.mdb \
	format/tst.format-p.mdb.out \
	options/tst.autowrap.mdb \
	options/tst.autowrap.mdb.out \
	typedef/err.badid-leadnum.ksh \
	typedef/err.badid-leadschar.ksh \
	typedef/err.badmodel.ksh \
	typedef/err.badstruct-extrabraces.ksh \
	typedef/err.badstruct-neglenarr.ksh \
	typedef/err.badstruct-noarrayclose.ksh \
	typedef/err.badstruct-noarraylen.ksh \
	typedef/err.badstruct-noarrayopen.ksh \
	typedef/err.badstruct-nobraces.ksh \
	typedef/err.badstruct-noclosebrace.ksh \
	typedef/err.badstruct-nomembers.ksh \
	typedef/err.badstruct-nomemname.ksh \
	typedef/err.badstruct-nomemsemi.ksh \
	typedef/err.badstruct-noopenbrace.ksh \
	typedef/err.badstruct-noquotes.ksh \
	typedef/err.badstruct-repmemname.ksh \
	typedef/err.badstruct-vlaonly.ksh \
	typedef/err.badstruct-zerolenarr.ksh \
	typedef/err.badunion-hasvla.ksh \
	typedef/err.extraargs.ksh \
	typedef/err.noargs.ksh \
	typedef/err.nokeyword.ksh \
	typedef/err.nomodel.ksh \
	typedef/err.noname.ksh \
	typedef/err.typeexists.ksh \
	typedef/tst.anonstruct.mdb \
	typedef/tst.anonstruct.mdb.out \
	typedef/tst.anonunion.mdb \
	typedef/tst.anonunion.mdb.out \
	typedef/tst.cleanupstruct.ksh \
	typedef/tst.deftypes32.mdb \
	typedef/tst.deftypes32.mdb.out \
	typedef/tst.deftypes64.mdb \
	typedef/tst.deftypes64.mdb.out \
	typedef/tst.dellist.mdb \
	typedef/tst.emptylist.mdb \
	typedef/tst.libctype.ksh \
	typedef/tst.libctype.ksh.out \
	typedef/tst.models.ksh \
	typedef/tst.struct.mdb \
	typedef/tst.struct.mdb.out \
	typedef/tst.structselfref.mdb \
	typedef/tst.structselfref.mdb.out \
	typedef/tst.structvla.mdb \
	typedef/tst.structvla.mdb.out \
	typedef/tst.union.mdb \
	typedef/tst.union.mdb.out \

ROOTFILES = $(FILES:%=$(TESTDIR)/%)
ROOTMAKEDIRS = $(MAKEDIRS:%=$(TESTDIR)/%)

FILEMODE = 0444

$(TESTDIR)/mdbtest := FILEMODE = 0555

all:

install: all $(ROOTFILES) $(ROOTPROG)

clean clobber:

$(ROOTFILES): $(TESTDIR) $(ROOTMAKEDIRS) $(FILES)

$(TESTDIR) $(ROOTMAKEDIRS):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
