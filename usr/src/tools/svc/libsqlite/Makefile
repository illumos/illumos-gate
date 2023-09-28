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

# Copyright 2023 Richard Lowe

include $(SRC)/lib/libsqlite/Makefile.com
include $(SRC)/tools/Makefile.tools

SRCDIR = $(SRC)/lib/libsqlite/src
TOOLDIR = $(SRC)/lib/libsqlite/tool

SQLITE_VERSION = 2.8.15-repcached
ENCODING  = ISO8859

NATIVE_LIBS += libc.so

CPPFLAGS += $(MYCPPFLAGS)

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-unused-function

LIBLINKS = libsqlite-sys.so

.KEEP_STATE:

$(PICS): sqlite.h

sqlite.h: $(SRCDIR)/sqlite.h.in
	@echo "Generating $@"; \
	 sed -e 's"--VERS--"$(SQLITE_VERSION)"' \
	    -e s/--ENCODING--/$(ENCODING)/ \
	    $(SRCDIR)/sqlite.h.in > $@

install: all $(ROOTONBLDLIBMACH)/$(DYNLIB) $(ROOTONBLDLIBMACH)/$(LIBLINKS)

$(ROOTONBLDLIBMACH)/$(DYNLIB): $(DYNLIB)
	$(INS.file) $(DYNLIB)

$(ROOTONBLDLIBMACH)/$(LIBLINKS): $(ROOTONBLDLIBMACH)/$(DYNLIB)
		@$(RM) $(ROOTONBLDLIBMACH)/$(LIBLINKS)
		$(SYMLINK) $(DYNLIB) $(ROOTONBLDLIBMACH)/$(LIBLINKS)


include $(SRC)/lib/libsqlite/Makefile.targ
