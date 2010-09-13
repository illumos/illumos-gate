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

# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.


include ../../Makefile.cmd
include ../../Makefile.cmd.64

PROG = compilercheck

SUNPERF = $(SPRO_VROOT)/prod/lib

SUNPV9B = $(SUNPERF)/v9b

INCLUDES = -I$(SPRO_VROOT)/prod/include/cc

CFLAGS64 += $(INCLUDES) -_gcc="-D__SUNPRO_C=1"

SRCS = fps_compiler_check.c

LINTFLAGS64 += $(INCLUDES) -D_sparc64 -DV9B -D__sparcv9

.KEEP_STATE:

########## beginning of dependency lines #################

all install : $(PROG)

$(PROG):fps_compiler_check.o
	$(LINK.c) -o $@ fps_compiler_check.o $(SUNPV9B)/libsunperf.a

clean:
	$(RM) fps_compiler_check.o

lint: lint_SRCS

include ../../Makefile.targ
