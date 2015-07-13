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

LIBRARY =	libmksh.a
VERS =		.1
OBJECTS =	dosys.o \
		globals.o \
		i18n.o \
		macro.o \
		misc.o \
		mksh.o \
		read.o

include $(SRC)/lib/Makefile.lib
include ../../Makefile.com

POFILE = libmksh.po
POFILES = $(OBJECTS:%.o=%.po)

LIBS = $(LIBRARY)
SRCDIR = ../
MAPFILES=
CPPFLAGS += -D_FILE_OFFSET_BITS=64

all: $(LIBS)

install: all

lint:

$(POFILE): $(POFILES)
	$(CAT) $(POFILES) > $@

_msg: $(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

include $(SRC)/lib/Makefile.targ
