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
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/boot/Makefile.inc

CPPFLAGS +=	-I../../include -I$(SASRC)
CPPFLAGS +=	-I../../sys -I.

include $(SASRC)/Makefile.inc
include $(CRYPTOSRC)/Makefile.inc
include $(ZFSSRC)/Makefile.inc

CPPFLAGS +=	-I$(SRC)/uts/common

# 64-bit smatch false positive :/
SMOFF += uninitialized

# needs work
objs/printf.o := SMOFF += 64bit_shift
pics/printf.o := SMOFF += 64bit_shift

machine:
	$(RM) machine
	$(SYMLINK) ../../sys/$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../sys/x86/include x86

pics/%.o objs/%.o:	%.c
	$(COMPILE.c) -o $@ $<

pics/%.o objs/%.o:	$(SASRC)/%.c
	$(COMPILE.c) -o $@ $<

pics/%.o objs/%.o:	$(SASRC)/string/%.c
	$(COMPILE.c) -o $@ $<

pics/%.o objs/%.o:	$(SASRC)/uuid/%.c
	$(COMPILE.c) -o $@ $<

pics/%.o objs/%.o:	$(ZLIB)/%.c
	$(COMPILE.c) -o $@ $<

pics/%.o objs/%.o:	$(LZ4)/%.c
	$(COMPILE.c) -o $@ $<

pics/%.o objs/%.o:	$(SRC)/common/util/%.c
	$(COMPILE.c) -o $@ $<

clean: clobber
clobber:
	$(RM) $(CLEANFILES) machine x86
