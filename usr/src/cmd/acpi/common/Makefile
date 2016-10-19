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
# Copyright 2016 Joyent, Inc.
#

LIBRARY =	acpi.a

include	$(SRC)/lib/Makefile.lib

OBJECTS= getopt.o osl.o utascii.o utdebug.o utexcep.o utglobal.o  utmath.o \
	utnonansi.o utprint.o utxferror.o
SRCS = $(OBJECTS:.o=.c)

CERRWARN += -_gcc=-Wno-unused-function

CPPFLAGS += -I$(SRC)/uts/intel/sys/acpi -DACPI_APPLICATION

LDLIBS += -lc

HSONAME=
MAPFILES = mapfile-vers

.KEEP_STATE:

all: $(LIBRARY)

install: all

include $(SRC)/lib/Makefile.targ
