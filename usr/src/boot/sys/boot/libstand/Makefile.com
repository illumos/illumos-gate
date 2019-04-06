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

CPPFLAGS +=	-I../../../../include -I$(SASRC)
CPPFLAGS +=	-I../../.. -I. -I$(SRC)/common/bzip2

$(LIBRARY): $(SRCS) $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

include $(SASRC)/Makefile.inc
include $(ZFSSRC)/Makefile.inc

CPPFLAGS +=	-I$(SRC)/uts/common

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) machine $(LIBRARY)

machine:
	$(RM) machine
	$(SYMLINK) ../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

%.o:	$(SASRC)/%.c
	$(COMPILE.c) $<

%.o:	$(LIBSRC)/libc/net/%.c
	$(COMPILE.c) $<

%.o:	$(LIBSRC)/libc/string/%.c
	$(COMPILE.c) $<

%.o:	$(LIBSRC)/libc/uuid/%.c
	$(COMPILE.c) $<

%.o:	$(ZLIB)/%.c
	$(COMPILE.c) $<
