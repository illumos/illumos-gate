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

PROGS = libjedec_hex2spd
OBJS = \
	libjedec_hex2spd.o	\
	libjedec_hex2spd_ddr3.o	\
	libjedec_hex2spd_ddr4.o	\
	libjedec_hex2spd_ddr5.o	\
	libjedec_hex2spd_lp3.o	\
	libjedec_hex2spd_lp4.o	\
	libjedec_hex2spd_lp5.o
SPD = \
	ddr3/M393B4G70BM0-CMA09.spd		\
	ddr3/MT36KSZF2G72LDZ-1G6E2A7.spd	\
	ddr4/36ASF8G72PZ-3G2E1.spd		\
	ddr4/AQD-D4U32N32-SBW.spd		\
	ddr4/AQD-SD4U16GN32-SE1.spd		\
	ddr4/M386AAK40B40-CWD70.spd		\
	ddr5/AQD-D5V16GR48-SB.spd		\
	ddr5/MTC40F2046S1RC48BA1.spd		\
	lpddr3/NT6CL256T32CQ.spd		\
	lpddr4/MT53D1024M32D4.spd		\
	lpddr5/CAMM2.spd			\
	lpddr5/MT62F4G32D8DV-023.spd
SPDDIR = ddr3 ddr4 ddr5 lpddr3 lpddr4 lpddr5

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)
OBJS32 = $(OBJS:%.o=%.32.o)
OBJS64 = $(OBJS:%.o=%.64.o)

ROOTOPTDIR = $(ROOT)/opt/util-tests/tests
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTDIR)/%) $(PROGS64:%=$(ROOTOPTDIR)/%)
ROOTOPTHEX = $(ROOTOPTDIR)/hex2spd
ROOTHEXDIRS = $(SPDDIR:%=$(ROOTOPTHEX)/%)
ROOTHEXSPD = $(SPD:%=$(ROOTOPTHEX)/%)

$(ROOTOPTPROGS) := FILEMODE = 0555
$(ROOTHEXSPD) := FILEMODE = 0444

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CTF_MODE = link
LDLIBS += -ljedec -lnvpair
LDLIBS64 += -ljedec -lnvpair

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS) $(ROOTHEXSPD)

clean:
	$(RM) *.o

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

$(ROOTOPTPROGS): $(ROOTOPTHEX)

$(ROOTHEXSPD): $(ROOTHEXDIRS)

$(ROOTOPTHEX):
	$(INS.dir)

$(ROOTHEXDIRS): $(ROOTOPTHEX)
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

$(ROOTOPTHEX)/%: data/%
	$(INS.file)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.64: $(OBJS64)
	$(LINK64.c) -o $@ $(OBJS64) $(LDLIBS64)
	$(POST_PROCESS)

%.32: $(OBJS32)
	$(LINK.c) -o $@ $(OBJS32) $(LDLIBS)
	$(POST_PROCESS)
