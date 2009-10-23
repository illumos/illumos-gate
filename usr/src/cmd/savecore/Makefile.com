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

PROG= savecore
SRCS= ../savecore.c ../../../uts/common/os/compress.c
OBJS= savecore.o compress.o

include ../../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -DBZ_NO_STDIO -I$(SRC)/uts/common

BZIP2OBJS =	bz2blocksort.o	\
		bz2compress.o	\
		bz2decompress.o	\
		bz2randtable.o	\
		bz2bzlib.o	\
		bz2crctable.o	\
		bz2huffman.o

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(BZIP2OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(BZIP2OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS) $(BZIP2OBJS)

lint:	lint_SRCS

include ../../Makefile.targ

%.o: ../%.c
	$(COMPILE.c) -I$(SRC)/common $<
	$(POST_PROCESS_O)

%.o: ../../../uts/common/os/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

bz2%.o: ../../../common/bzip2/%.c
	$(COMPILE.c) -o $@ -I$(SRC)/common -I$(SRC)/common/bzip2 $<
	$(POST_PROCESS_O)
