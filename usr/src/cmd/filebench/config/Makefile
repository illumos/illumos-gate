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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.KEEP_STATE:

include ../../Makefile.cmd

CONFIGS = fileio.prof filemacro.prof filemicro.prof generic.func \
seqread.prof randomread.prof multi_fileserver.prof newfeatures.prof \
videoserver.prof
ROOTUSRBENCHDIR = $(ROOT)/usr/benchmarks
ROOTUSRBENCHFBCONFIGDIR = $(ROOTUSRBENCHDIR)/filebench/config
FBCONFIGS = $(CONFIGS:%=$(ROOTUSRBENCHFBCONFIGDIR)/%)

FILEMODE= 0444

all clobber clean lint:

$(ROOTUSRBENCHDIR):
	$(INS.dir)

$(ROOTUSRBENCHFBCONFIGDIR):
	$(INS.dir)

$(ROOTUSRBENCHFBCONFIGDIR)/%:%
	$(INS.file)

install: $(ROOTUSRBENCHDIR) .WAIT $(ROOTUSRBENCHFBCONFIGDIR) .WAIT $(FBCONFIGS)
