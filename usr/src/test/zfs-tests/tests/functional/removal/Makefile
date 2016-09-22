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
# Copyright (c) 2014, 2017 by Delphix. All rights reserved.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TESTDIR = $(ROOTOPTPKG)/tests/functional/removal

PROGS = cleanup \
        removal_all_vdev \
        removal_check_space \
        removal_condense_export \
        removal_multiple_indirection \
        removal_remap \
        removal_reservation \
        removal_sanity \
        removal_remap_deadlists \
        removal_with_add \
        removal_with_create_fs \
        removal_with_dedup \
        removal_with_export \
        removal_with_ganging \
        removal_with_remap \
        removal_with_remove \
        removal_with_scrub \
        removal_with_send \
        removal_with_send_recv \
        removal_with_snapshot \
        removal_with_write \
        removal_with_zdb \
        removal_resume_export \
        remove_mirror \
        remove_mirror_sanity \
        remove_raidz

FILES = removal.kshlib

CMDS = $(PROGS:%=$(TESTDIR)/%) $(FILES:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all lint clean clobber:

install: $(CMDS)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

$(TESTDIR)/%: %
	$(INS.file)
