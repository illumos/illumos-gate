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

# Copyright 2019, Richard Lowe.

include ../../../Makefile.master

#
# To build a proper 'tools' version of the link-editor is not possible, as
# we'll always depend on the ELF-related headers from the workspace, not the
# system.
#
# We pull in the minimum amount of headers using an explicit list of "ELF-y"
# headers to populate this directory, which we then search while building.
#
# This may not be enough on all occasions, judgement must be used to decide
# between providing extra headers, and wrapping problematic code in conditions
# on NATIVE_BUILD for a period of time.
#

ROOTHDRS=	dlfcn.h \
		gelf.h \
		libelf.h \
		proc_service.h \
		rtld_db.h \
		link.h

SYSHDRS=	sys/elf.h \
		sys/elf_386.h \
		sys/elf_SPARC.h \
		sys/elf_notes.h \
		sys/elf_amd64.h \
		sys/elftypes.h \
		sys/auxv.h \
		sys/auxv_SPARC.h \
		sys/auxv_386.h \
		sys/avl.h \
		sys/link.h \
		sys/machelf.h \
		sys/note.h \
		sys/systeminfo.h

sys:
	$(MKDIR) -p sys

%: $(SRC)/head/%
	$(INS.file)

sys/%: sys $(SRC)/uts/common/sys/%
	$(INS.file)

all install: $(SYSHDRS) $(ROOTHDRS)

clean:

clobber: clean
	$(RM) $(SYSHDRS) $(ROOTHDRS)



