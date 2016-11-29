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
# Copyright (c) 2013, 2015 by Delphix. All rights reserved.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TESTDIR = $(ROOTOPTPKG)/tests/functional/rsend

PROGS = cleanup \
	rsend_001_pos \
	rsend_002_pos \
	rsend_003_pos \
	rsend_004_pos \
	rsend_005_pos \
	rsend_006_pos \
	rsend_007_pos \
	rsend_008_pos \
	rsend_009_pos \
	rsend_010_pos \
	rsend_011_pos \
	rsend_012_pos \
	rsend_013_pos \
	rsend_014_pos \
	rsend_019_pos \
	rsend_020_pos \
	rsend_021_pos \
	rsend_022_pos \
	rsend_024_pos \
	send-cD \
	send-c_embedded_blocks \
	send-c_incremental \
	send-c_lz4_disabled \
	send-c_mixed_compression \
	send-c_props \
	send-c_recv_dedup \
	send-c_recv_lz4_disabled \
	send-c_resume \
	send-c_stream_size_estimate \
	send-c_verify_contents \
	send-c_verify_ratio \
	send-c_volume \
	send-c_zstreamdump \
	send-cpL_varied_recsize \
	setup

FILES = rsend.cfg \
	rsend.kshlib

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
