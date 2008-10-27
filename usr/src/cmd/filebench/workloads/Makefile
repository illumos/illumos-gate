#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.KEEP_STATE:

include ../../Makefile.cmd

WORKLOADS = \
	bringover.f \
	compflow_demo.f \
	copyfiles.f \
	createfiles.f \
	deletefiles.f \
	filemicro_create.f \
	filemicro_createfiles.f \
	filemicro_createrand.f \
	filemicro_delete.f \
	filemicro_rread.f \
	filemicro_rwrite.f \
	filemicro_rwritedsync.f \
	filemicro_rwritefsync.f \
	filemicro_seqwriterandvargam.f \
	filemicro_seqwriterandvartab.f \
	filemicro_seqread.f \
	filemicro_seqwrite.f \
	filemicro_seqwriterand.f \
	filemicro_statfile.f \
	filemicro_writefsync.f \
	fileserver.f \
	listdirs.f \
	makedirs.f \
	mongo.f \
	multistreamread.f \
	multistreamreaddirect.f \
	multistreamwrite.f \
	multistreamwritedirect.f \
	oltp.f \
	openfiles.f \
	randomread.f \
	randomrw.f \
	randomwrite.f \
	ratelimcopyfiles.f \
	removedirs.f \
	singlestreamread.f \
	singlestreamreaddirect.f \
	singlestreamwrite.f \
	singlestreamwritedirect.f \
	tpcso.f \
	varmail.f \
	videoserver.f \
	webproxy.f \
	webserver.f

ROOTUSRBENCHDIR = $(ROOT)/usr/benchmarks
ROOTUSRBENCHFBWORKLOADSDIR = $(ROOTUSRBENCHDIR)/filebench/workloads
FBWORKLOADS = $(WORKLOADS:%=$(ROOTUSRBENCHFBWORKLOADSDIR)/%)

FILEMODE= 0444

all clobber clean lint:

$(ROOTUSRBENCHDIR):
	$(INS.dir)

$(ROOTUSRBENCHFBWORKLOADSDIR):
	$(INS.dir)

$(ROOTUSRBENCHFBWORKLOADSDIR)/%: %
	$(INS.file)

install: $(ROOTUSRBENCHDIR) .WAIT $(ROOTUSRBENCHFBWORKLOADSDIR) .WAIT $(FBWORKLOADS)
