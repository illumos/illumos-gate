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
# Copyright 2018 Joyent, Inc.
#

include $(SRC)/lib/libctf/Makefile.shared.com
include ../../Makefile.ctf

CSTD = $(CSTD_GNU99)
C99LMODE = -Xc99=%all

CPPFLAGS +=	-I$(SRC)/lib/libctf/common/ \
		-I$(SRC)/lib/libdwarf/common/ \
		-I$(SRC)/lib/mergeq \
		-include ../../common/ctf_headers.h \
		-DCTF_OLD_VERSIONS \
		-DCTF_TOOLS_BUILD
LDLIBS += -lc -lelf -L$(ROOTONBLDLIBMACH) -ldwarf -lavl
NATIVE_LIBS += libelf.so libavl.so libc.so
DYNFLAGS += '-R$$ORIGIN/../../lib/$(MACH)'

.KEEP_STATE:

all: $(LIBS)

install: all $(ROOTONBLDLIBMACH)/libctf.so.1 $(ROOTONBLDLIBMACH)/libctf.so

$(ROOTONBLDLIBMACH)/%: %
	$(INS.file)

$(ROOTONBLDLIBMACH)/$(LIBLINKS): $(ROOTONBLDLIBMACH)/$(LIBLINKS)$(VERS)
	$(INS.liblink)

#
# Just like with libdwarf, we can't actually add ctf to ourselves,
# because we're part of the tools for creating CTF.
#
$(DYNLIB) := CTFMERGE_POST= :
CTFCONVERT_O= :

include $(SRC)/lib/Makefile.targ
include $(SRC)/lib/libctf/Makefile.shared.targ
