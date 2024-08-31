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

PROG=		acpixtract

include ../../Makefile.cmd
include ../../Makefile.ctf

OBJS =	axmain.o acpixtract.o axutils.o osunixxf.o utglobal.o getopt.o \
	utdebug.o osl.o utascii.o utmath.o utxferror.o utnonansi.o \
	utexcep.o
SRCS = $(OBJS:.o=.c)

VPATH = ../common:$(SRC)/common/acpica/utilities

#
# "the 'AX_IS_TABLE_BLOCK_HEADER' macro might need parens"
# (Reported) upstream bug.
#
SMOFF = all_func_returns,macros

CPPFLAGS += -I$(SRC)/uts/intel/sys/acpi -DACPI_XTRACT_APP
CPPFLAGS += -DACPI_DATE=\"`$(ECHO) $(VERSION) | sed -e 's/ /_/g'`\"

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
