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
# Copyright 2019 Joyent, Inc.
# Copyright 2023 Oxide Computer Company
#

include ../../Makefile.cmd
include ../../Makefile.ctf

SRCS += mcdecode.c imc_decode.c imc_dump.c
SRCS += zen_fabric_utils.c zen_umc_decode.c zen_umc_dump.c bitext.o
OBJS = $(SRCS:%.c=%.o)

PROG = mcdecode

ROOTLIBFM = $(ROOT)/usr/lib/fm
ROOTLIBFMD = $(ROOT)/usr/lib/fm/fmd
ROOTPROG = $(ROOTLIBFMD)/$(PROG)

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG
CPPFLAGS += -I$(SRC)/uts/intel/io/imc
CPPFLAGS += -I$(SRC)/uts/intel/io/amdzen -I$(SRC)/uts/intel
LDLIBS += -lnvpair

CSTD = $(CSTD_GNU99)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/bitext/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/mc/imc/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/mc/zen_umc/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/amdzen/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

clean:
	$(RM) $(OBJS) $(LINTFILES)

clobber: clean
	$(RM) $(PROG)

$(ROOTLIBFMD)/%: %
	$(INS.file)

install_h:

install: all $(ROOTPROG)
