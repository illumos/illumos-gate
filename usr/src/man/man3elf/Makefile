#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	3elf

MANFILES=	elf.3elf		\
		elf32_checksum.3elf	\
		elf32_fsize.3elf	\
		elf32_getehdr.3elf	\
		elf32_getphdr.3elf	\
		elf32_getshdr.3elf	\
		elf32_xlatetof.3elf	\
		elf_begin.3elf		\
		elf_cntl.3elf		\
		elf_errmsg.3elf		\
		elf_fill.3elf		\
		elf_flagdata.3elf	\
		elf_getarhdr.3elf	\
		elf_getarsym.3elf	\
		elf_getbase.3elf	\
		elf_getdata.3elf	\
		elf_getident.3elf	\
		elf_getscn.3elf		\
		elf_hash.3elf		\
		elf_kind.3elf		\
		elf_rawfile.3elf	\
		elf_strptr.3elf		\
		elf_update.3elf		\
		elf_version.3elf	\
		gelf.3elf		\
		nlist.3elf

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
