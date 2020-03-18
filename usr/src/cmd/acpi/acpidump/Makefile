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
# Copyright 2020 Joyent, Inc.
# Copyright 2016 RackTop Systems.
#

PROG=		acpidump

include ../../Makefile.cmd
include ../../Makefile.ctf

OBJS= apmain.o apdump.o apfiles.o getopt.o tbprint.o tbxfroot.o osillumostbl.o \
	utascii.o utbuffer.o utdebug.o utexcep.o utmath.o utnonansi.o \
	utxferror.o utglobal.o osunixdir.o osl.o osunixxf.o \
	uthex.o utstrsuppt.o utstrtoul64.o
SRCS = $(OBJS:.o=.c)

VPATH = ../common:$(SRC)/common/acpica/utilities:$(SRC)/common/acpica/tables

CERRWARN += -_gcc=-Wno-unused-function

SMOFF = all_func_returns

CPPFLAGS += -I$(SRC)/uts/intel/sys/acpi -DACPI_DUMP_APP

LDLIBS += -ldevinfo

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(PROG)

lint:	lint_SRCS

include ../../Makefile.targ
