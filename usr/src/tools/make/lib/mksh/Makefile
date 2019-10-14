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

# Copyright 2015, Richard Lowe.
# Copyright 2019 RackTop Systems.

LIBRARY = libmksh.a
VERS = .1
OBJECTS = dosys.o globals.o i18n.o macro.o misc.o mksh.o read.o

include $(SRC)/lib/Makefile.lib
include ../../Makefile.com

LIBS = $(LIBRARY)
SRCDIR = $(SRC)/cmd/make/lib/mksh
MAPFILES=
CPPFLAGS += -D_FILE_OFFSET_BITS=64

CCERRWARN += -_gcc=-Wno-unused-variable
CCERRWARN += -_gcc=-Wno-unused-function
CCERRWARN += -_gcc=-Wno-unused-value
CCERRWARN += -_gcc=-Wno-uninitialized

all: $(LIBS)

install: all

lint:

# We can't create CTF in the tools build because of a bootstrap bug with the new CTF
$(DYNLIB) := CTFMERGE_POST= :
CTFCONVERT_O= :

include $(SRC)/lib/Makefile.targ
