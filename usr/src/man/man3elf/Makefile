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

MANSECT= 	3elf

MANFILES= 	elf.3elf		\
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

MANLINKS=	elf32_newehdr.3elf		\
		elf32_newphdr.3elf		\
		elf32_xlatetom.3elf		\
		elf64_checksum.3elf		\
		elf64_fsize.3elf		\
		elf64_getehdr.3elf		\
		elf64_getphdr.3elf		\
		elf64_getshdr.3elf		\
		elf64_newehdr.3elf		\
		elf64_newphdr.3elf		\
		elf64_xlatetof.3elf		\
		elf64_xlatetom.3elf		\
		elf_end.3elf			\
		elf_errno.3elf			\
		elf_flagehdr.3elf		\
		elf_flagelf.3elf		\
		elf_flagphdr.3elf		\
		elf_flagscn.3elf		\
		elf_flagshdr.3elf		\
		elf_getphdrnum.3elf		\
		elf_getphnum.3elf		\
		elf_getshdrnum.3elf		\
		elf_getshdrstrndx.3elf		\
		elf_getshnum.3elf		\
		elf_getshstrndx.3elf		\
		elf_memory.3elf			\
		elf_ndxscn.3elf			\
		elf_newdata.3elf		\
		elf_newscn.3elf			\
		elf_next.3elf			\
		elf_nextscn.3elf		\
		elf_rand.3elf			\
		elf_rawdata.3elf		\
		gelf_checksum.3elf		\
		gelf_fsize.3elf			\
		gelf_getcap.3elf		\
		gelf_getclass.3elf		\
		gelf_getdyn.3elf		\
		gelf_getehdr.3elf		\
		gelf_getmove.3elf		\
		gelf_getphdr.3elf		\
		gelf_getrel.3elf		\
		gelf_getrela.3elf		\
		gelf_getshdr.3elf		\
		gelf_getsym.3elf		\
		gelf_getsyminfo.3elf		\
		gelf_getsymshndx.3elf		\
		gelf_newehdr.3elf		\
		gelf_newphdr.3elf		\
		gelf_update_cap.3elf		\
		gelf_update_dyn.3elf		\
		gelf_update_ehdr.3elf		\
		gelf_update_getmove.3elf	\
		gelf_update_move.3elf		\
		gelf_update_phdr.3elf		\
		gelf_update_rel.3elf		\
		gelf_update_rela.3elf		\
		gelf_update_shdr.3elf		\
		gelf_update_sym.3elf		\
		gelf_update_syminfo.3elf	\
		gelf_update_symshndx.3elf	\
		gelf_xlatetof.3elf		\
		gelf_xlatetom.3elf

elf64_checksum.3elf		:= LINKSRC = elf32_checksum.3elf

elf64_fsize.3elf		:= LINKSRC = elf32_fsize.3elf

elf32_newehdr.3elf		:= LINKSRC = elf32_getehdr.3elf
elf64_getehdr.3elf		:= LINKSRC = elf32_getehdr.3elf
elf64_newehdr.3elf		:= LINKSRC = elf32_getehdr.3elf
elf32_newphdr.3elf		:= LINKSRC = elf32_getphdr.3elf
elf64_getphdr.3elf		:= LINKSRC = elf32_getphdr.3elf
elf64_newphdr.3elf		:= LINKSRC = elf32_getphdr.3elf
elf64_getshdr.3elf		:= LINKSRC = elf32_getshdr.3elf

elf32_xlatetom.3elf		:= LINKSRC = elf32_xlatetof.3elf
elf64_xlatetof.3elf		:= LINKSRC = elf32_xlatetof.3elf
elf64_xlatetom.3elf		:= LINKSRC = elf32_xlatetof.3elf

elf_end.3elf			:= LINKSRC = elf_begin.3elf
elf_memory.3elf			:= LINKSRC = elf_begin.3elf
elf_next.3elf			:= LINKSRC = elf_begin.3elf
elf_rand.3elf			:= LINKSRC = elf_begin.3elf

elf_errno.3elf			:= LINKSRC = elf_errmsg.3elf

elf_flagehdr.3elf		:= LINKSRC = elf_flagdata.3elf
elf_flagelf.3elf		:= LINKSRC = elf_flagdata.3elf
elf_flagphdr.3elf		:= LINKSRC = elf_flagdata.3elf
elf_flagscn.3elf		:= LINKSRC = elf_flagdata.3elf
elf_flagshdr.3elf		:= LINKSRC = elf_flagdata.3elf

elf_newdata.3elf		:= LINKSRC = elf_getdata.3elf
elf_rawdata.3elf		:= LINKSRC = elf_getdata.3elf

elf_getphdrnum.3elf		:= LINKSRC = elf_getident.3elf
elf_getphnum.3elf		:= LINKSRC = elf_getident.3elf
elf_getshdrnum.3elf		:= LINKSRC = elf_getident.3elf
elf_getshdrstrndx.3elf		:= LINKSRC = elf_getident.3elf
elf_getshnum.3elf		:= LINKSRC = elf_getident.3elf
elf_getshstrndx.3elf		:= LINKSRC = elf_getident.3elf

elf_ndxscn.3elf			:= LINKSRC = elf_getscn.3elf
elf_newscn.3elf			:= LINKSRC = elf_getscn.3elf
elf_nextscn.3elf		:= LINKSRC = elf_getscn.3elf

gelf_checksum.3elf		:= LINKSRC = gelf.3elf
gelf_fsize.3elf			:= LINKSRC = gelf.3elf
gelf_getcap.3elf		:= LINKSRC = gelf.3elf
gelf_getclass.3elf		:= LINKSRC = gelf.3elf
gelf_getdyn.3elf		:= LINKSRC = gelf.3elf
gelf_getehdr.3elf		:= LINKSRC = gelf.3elf
gelf_getmove.3elf		:= LINKSRC = gelf.3elf
gelf_getphdr.3elf		:= LINKSRC = gelf.3elf
gelf_getrel.3elf		:= LINKSRC = gelf.3elf
gelf_getrela.3elf		:= LINKSRC = gelf.3elf
gelf_getshdr.3elf		:= LINKSRC = gelf.3elf
gelf_getsym.3elf		:= LINKSRC = gelf.3elf
gelf_getsyminfo.3elf		:= LINKSRC = gelf.3elf
gelf_getsymshndx.3elf		:= LINKSRC = gelf.3elf
gelf_newehdr.3elf		:= LINKSRC = gelf.3elf
gelf_newphdr.3elf		:= LINKSRC = gelf.3elf
gelf_update_cap.3elf		:= LINKSRC = gelf.3elf
gelf_update_dyn.3elf		:= LINKSRC = gelf.3elf
gelf_update_ehdr.3elf		:= LINKSRC = gelf.3elf
gelf_update_getmove.3elf	:= LINKSRC = gelf.3elf
gelf_update_move.3elf		:= LINKSRC = gelf.3elf
gelf_update_phdr.3elf		:= LINKSRC = gelf.3elf
gelf_update_rel.3elf		:= LINKSRC = gelf.3elf
gelf_update_rela.3elf		:= LINKSRC = gelf.3elf
gelf_update_shdr.3elf		:= LINKSRC = gelf.3elf
gelf_update_sym.3elf		:= LINKSRC = gelf.3elf
gelf_update_syminfo.3elf	:= LINKSRC = gelf.3elf
gelf_update_symshndx.3elf	:= LINKSRC = gelf.3elf
gelf_xlatetof.3elf		:= LINKSRC = gelf.3elf
gelf_xlatetom.3elf		:= LINKSRC = gelf.3elf

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
