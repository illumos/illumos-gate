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
# Copyright 2012, Richard Lowe.
#

include $(SRC)/Makefile.master
include $(SRC)/Makefile.master.64

.KEEP_STATE:

PROGS = align \
	basic \
	big-struct-ret \
	big-struct-ret-and-spill \
	small-struct-ret \
	small-struct-ret-and-spill \
	stack-spill

CFLAGS += $(CTF_FLAGS)
CFLAGS64 += $(CTF_FLAGS)

%: %.c
	$(LINK.c) -o $@ $< -lc
	$(CTFCONVERT) -L VERSION $@

all: $(PROGS)

install: all

clean:
	$(RM) $(PROGS)

clobber: clean

FRC:
