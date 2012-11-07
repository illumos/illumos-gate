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

PROG     = fruadm
PLATFORM = sun4u
CLASS    = 32     #  so ParallelMake isn't confused by empty rules

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/Makefile.psm

FRULIBS    = -L$(SRC)/lib/libfru/$(MACH) -lfru

CFLAGS    += $(CCVERBOSE)
CERRWARN  += -_gcc=-Wno-switch
CPPFLAGS  += -I$(SRC)/lib/libfru/include
LINTFLAGS += -u
LDLIBS    += $(FRULIBS) -lm

lint      := FRULIBS =

FILEMODE = 755

.KEEP_STATE:

all: $(PROG)

install: all $(USR_PSM_SBIN_DIR) $(USR_PSM_SBIN_PROG)

clean:

lint:	lint_PROG

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.psm.targ
