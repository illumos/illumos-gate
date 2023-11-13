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
# Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 Joyent, Inc.
#

PROG= savecore
OBJS= savecore.o compress.o

include ../Makefile.cmd
include ../Makefile.cmd.64

CSTD = $(CSTD_GNU99)

CFLAGS += $(CCVERBOSE)
CPPFLAGS += -DBZ_NO_STDIO -I$(SRC)/common -I$(SRC)/uts/common

LDLIBS += -L$(ROOT)/usr/lib/fm/64 -lfmevent -lnvpair
LDFLAGS += -R/usr/lib/fm/64

# not linted
SMATCH=off

#
# savecore is compiled with bits from $(SRC)/common/bzip2 and some function
# symbols there are defined as weak; if you leave them out of
# savecore.c it will compile, but trying to call that function
# will jump to 0.  So we use -ztext to avoid that.
#
LDFLAGS += $(ZTEXT)

BZIP2OBJS =	bz2blocksort.o	\
		bz2compress.o	\
		bz2decompress.o	\
		bz2randtable.o	\
		bz2bzlib.o	\
		bz2crctable.o	\
		bz2huffman.o

CHACHAOBJ = chacha.o

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

$(PROG): $(OBJS) $(BZIP2OBJS) $(CHACHAOBJ)
	$(LINK.c) -o $(PROG) $(OBJS) $(BZIP2OBJS) $(CHACHAOBJ) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS) $(BZIP2OBJS)

include ../Makefile.targ

%.o: ../../uts/common/os/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

bz2%.o: ../../common/bzip2/%.c
	$(COMPILE.c) -o $@ -I$(SRC)/common/bzip2 $<
	$(POST_PROCESS_O)

%.o: ../../common/crypto/chacha/%.c
	$(COMPILE.c) -o $@ -I$(SRC)/common -I$(SRC)/common/crypto/chacha $<
	$(POST_PROCESS_O)
