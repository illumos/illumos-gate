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
# Copyright 2025 Oxide Computer Company
#

PROG = i2csimd
OBJS = i2csimd.o \
	i2csimd_at24c.o \
	i2csimd_pca9548.o \
	i2csimd_ts511x.o \
	bitext.o
MANIFEST = i2csimd.xml

ROOTOPTDIR = $(ROOT)/opt/i2c-tests/svc
ROOTOPTPROGS = $(PROG:%=$(ROOTOPTDIR)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CPPFLAGS += -I$(SRC)/uts/common/io/i2c/ctrl/i2csim
CTF_MODE = link
ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

$(ROOTMANIFEST) := FILEMODE = 0444

.KEEP_STATE:

all: $(PROG)

install: $(ROOTOPTPROGS) $(ROOTMANIFEST)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: % $(ROOTOPTDIR)
	$(INS.file)

%.o: $(SRC)/common/bitext/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

clobber: clean
	$(RM) $(PROG)

check: $(CHKMANIFEST)
