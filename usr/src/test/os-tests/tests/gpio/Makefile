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
# Copyright 2022 Oxide Computer Company
#

include $(SRC)/cmd/Makefile.cmd

PROGS = \
	dpio_test \
	gpio_attr \
	gpio_lookup

SCRIPTS = \
	gpio_init \
	gpio_fini \
	gpioadm_test

DATA = \
	attr-g0_0-H.out \
	attr-g0_0-Ho.out \
	attr-g0_0-o.out \
	attr-g0_0-p.out \
	attr-g0_0.out \
	attr-g0_0_filt-p.out \
	attr-g0_0_filt.out \
	ctrl-list-H-sim1.out \
	ctrl-list-H.out \
	ctrl-list-dpio-p.out \
	ctrl-list-p-sim1.out \
	ctrl-list-p.out \
	ctrl-list-sim1.out \
	ctrl-list.out \
	dpio-H.out \
	dpio-Ho.out \
	dpio-o.out \
	dpio-p.out \
	dpio.out \
	gpio-period500-H.out \
	gpio-period500-o.out \
	gpio-period500-p.out \
	gpio-period500.out \
	gpio-sim0-H.out \
	gpio-sim0-o.out \
	gpio-sim0-p.out \
	gpio-sim0.out \
	gpio-sim01-H.out \
	gpio-sim01-o.out \
	gpio-sim01-p.out \
	gpio-sim01.out

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTGPIO = $(ROOTOPTDIR)/gpio
ROOTOPTGPIODATA = $(ROOTOPTDIR)/gpio/data
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTGPIO)/%) \
	$(PROGS64:%=$(ROOTOPTGPIO)/%) \
	$(SCRIPTS:%=$(ROOTOPTGPIO)/%)
ROOTOPTDATA = $(DATA:%=$(ROOTOPTGPIODATA)/%)
$(ROOTOPTDATA) := FILEMODE = 0444
CSTD = $(CSTD_GNU17)

gpio_attr.32 := LDLIBS += -lnvpair
gpio_attr.64 := LDLIBS64 += -lnvpair

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS) $(ROOTOPTDATA)

clean:

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTGPIO)
$(ROOTOPTDATA): $(ROOTOPTGPIODATA)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTGPIO): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTGPIODATA): $(ROOTOPTGPIO)
	$(INS.dir)

$(ROOTOPTGPIO)/%: %
	$(INS.file)

$(ROOTOPTGPIODATA)/%: data/%
	$(INS.file)

$(ROOTOPTGPIO)/%: %.ksh
	$(INS.rename)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber:
	$(RM) $(PROGS32) $(PROGS64)

FRC:
