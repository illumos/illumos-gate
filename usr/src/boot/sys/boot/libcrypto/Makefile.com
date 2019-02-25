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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master
include $(SRC)/boot/sys/boot/Makefile.inc

COMDIR = ../../../../../common/crypto

install:

SRCS +=	sha1.c digest.c
OBJS += sha1.o digest.o

CPPFLAGS += -I. -I../../../../include -I../../..
CPPFLAGS += -I../../../../lib/libstand

# Pick up the bootstrap header for some interface items
CPPFLAGS += -I../../common

# For multiboot2.h, must be last, to avoid conflicts
CPPFLAGS +=	-I$(SRC)/uts/common

.PARALLEL:

libcrypto.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) libcrypto.a

machine:
	$(RM) machine
	$(SYMLINK) ../../../${MACHINE}/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

%.o:	../%.c
	$(COMPILE.c) $<

%.o:	../../../../../common/crypto/sha1/%.c
	$(COMPILE.c) $<

sha1-x86_64.s: $(COMDIR)/sha1/amd64/sha1-x86_64.pl
	$(PERL) $? $@

sha1-x86_64.o: sha1-x86_64.s
	$(COMPILE.s) -o $@ ${@F:.o=.s}
