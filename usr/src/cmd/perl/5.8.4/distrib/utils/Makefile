#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

.KEEP_STATE:

include ../../../../Makefile.cmd
include ../../Makefile.perlcfg
 
PL_SRCS = \
    c2ph.PL \
    cpan.PL \
    dprofpp.PL \
    enc2xs.PL \
    h2ph.PL \
    h2xs.PL \
    instmodsh.PL \
    libnetcfg.PL \
    perlbug.PL \
    perlcc.PL \
    perldoc.PL \
    perlivp.PL \
    piconv.PL \
    pl2pm.PL \
    prove.PL \
    splain.PL \
    xsubpp.PL

PL_TARGS = $(PL_SRCS:%.PL=%)

TARGS = $(PL_TARGS)
CLOBBERFILES = $(TARGS) pstruct

all: $(TARGS)

$(PL_TARGS):
	$(RUN_MINIPERL) $@.PL

.PARALLEL: $(PL_TARGS)

$(PL_TARGS): ../lib/Config.pm

perlbug: ../patchlevel.h

splain: ../lib/diagnostics.pm

clean:

include ../../../../Makefile.targ
