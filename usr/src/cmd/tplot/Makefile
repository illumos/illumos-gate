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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

TPROG= t4014 t300 t300s t450
PROG= $(TPROG) vplot
SHFILES= tplot

# include common definitions
include ../Makefile.cmd

CLOBBERFILES += $(SHFILES)

# conditional assignments
t% := LDLIBS += -l$(@F:t%=%)
t% := MAPFILES = $(MAPFILE.INT) $(MAPFILE.NGB)
t% := LDFLAGS += $(MAPFILES:%=-M%)

.KEEP_STATE:

all: $(PROG) $(SHFILES)

$(TPROG): driver.o $$(MAPFILES)
	$(LINK.c) -o $@ driver.o $(LDLIBS)
	$(POST_PROCESS)

$(ROOTSHFILES):	$(SHFILES)

vplot: vplot.o banner.o
	$(LINK.c) -o $@ vplot.o banner.o $(LDLIBS)
	$(POST_PROCESS)

install: $(ROOTLIBPROG) $(ROOTSHFILES)

clean:
	$(RM) driver.o vplot.o banner.o

lint:
	$(LINT.c) driver.c $(LDLIBS) -l4014
	$(LINT.c) driver.c $(LDLIBS) -l300
	$(LINT.c) driver.c $(LDLIBS) -l300s
	$(LINT.c) driver.c $(LDLIBS) -l450
	$(LINT.c) vplot.c banner.c $(LDLIBS)

# include common targets
include ../Makefile.targ
