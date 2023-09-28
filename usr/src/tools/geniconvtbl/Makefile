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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.KEEP_STATE:

include	$(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/geniconvtbl/Makefile.com
include $(SRC)/tools/Makefile.tools

CPPFLAGS	= -I. -I$(SRCDIR)
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-implicit-function-declaration
YFLAGS		+= -d
CFLAGS		+= -D_FILE_OFFSET_BITS=64

LDLIBS		+= -lgen -lc
NATIVE_LIBS	+= libgen.so libc.so

install: $(ROOTONBLDMACHPROG)

all: $(PROG)
