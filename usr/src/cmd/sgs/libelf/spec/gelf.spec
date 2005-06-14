#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sgs/libelf/spec/gelf.spec

function	gelf_getsymshndx
include		<gelf.h>
declaration	GElf_Sym *gelf_getsymshndx(Elf_Data *symdata, \
			Elf_Data *shndxdata, int ndx, \
			GElf_Sym *symptr, Elf32_Word *xshndx);
version		SUNW_1.4
end		

function	gelf_update_symshndx
include		<gelf.h>
declaration	int gelf_update_symshndx(Elf_Data *symdata, \
			Elf_Data *shndxdata, int ndx, \
			GElf_Sym *symptr, Elf32_Word xshndx);
version		SUNW_1.4
end		

function	gelf_checksum
include		<gelf.h>
declaration	long gelf_checksum(Elf *elf)
version		SUNW_1.3
end		

function	gelf_getclass
include		<gelf.h>
declaration	int gelf_getclass(Elf *elf)
version		SUNW_1.2
end		

function	gelf_fsize
include		<gelf.h>
declaration	size_t gelf_fsize(Elf *elf, Elf_Type type, size_t count, unsigned ver)
version		SUNW_1.2
end		

function	gelf_getehdr
include		<gelf.h>
declaration	GElf_Ehdr *gelf_getehdr(Elf *elf, GElf_Ehdr *dst)
version		SUNW_1.2
end		

function	gelf_update_ehdr
include		<gelf.h>
declaration	int gelf_update_ehdr(Elf *elf, GElf_Ehdr *src)
version		SUNW_1.2
end		

function	gelf_newehdr
include		<gelf.h>
declaration	unsigned long gelf_newehdr(Elf *elf, int elfclass)
version		SUNW_1.2
end		

function	gelf_getphdr
include		<gelf.h>
declaration	GElf_Phdr *gelf_getphdr(Elf *elf, int ndx, GElf_Phdr *dst)
version		SUNW_1.2
end		

function	gelf_update_phdr
include		<gelf.h>
declaration	int gelf_update_phdr(Elf *elf, int ndx, GElf_Phdr *src)
version		SUNW_1.2
end		

function	gelf_newphdr
include		<gelf.h>
declaration	unsigned long gelf_newphdr(Elf *elf, size_t phnum)
version		SUNW_1.2
end		

function	gelf_getshdr
include		<gelf.h>
declaration	GElf_Shdr *gelf_getshdr(Elf_Scn *scn, GElf_Shdr *dst)
version		SUNW_1.2
end		

function	gelf_update_shdr
include		<gelf.h>
declaration	int gelf_update_shdr(Elf_Scn *scn, GElf_Shdr *src)
version		SUNW_1.2
end		

function	gelf_xlatetof
include		<gelf.h>
declaration	Elf_Data *gelf_xlatetof(Elf *elf, Elf_Data *dst, \
			const Elf_Data *src, unsigned encode)
version		SUNW_1.2
end		

function	gelf_xlatetom
include		<gelf.h>
declaration	Elf_Data *gelf_xlatetom(Elf *elf, Elf_Data *dst, \
			const Elf_Data * src, unsigned encode)
version		SUNW_1.2
end		

function	gelf_getsym
include		<gelf.h>
declaration	GElf_Sym *gelf_getsym(Elf_Data *data, int ndx, GElf_Sym *dst)
version		SUNW_1.2
end		

function	gelf_update_sym
include		<gelf.h>
declaration	int gelf_update_sym(Elf_Data *dest, int ndx, GElf_Sym *src)
version		SUNW_1.2
end		

function	gelf_getsyminfo
include		<gelf.h>
declaration	GElf_Syminfo *gelf_getsyminfo(Elf_Data *data, int ndx, GElf_Syminfo *dst)
version		SUNW_1.2
end		

function	gelf_getmove
include		<gelf.h>
declaration	GElf_Move *gelf_getmove(Elf_Data * data, int ndx, GElf_Move *src)
version		SUNW_1.2
end		

function	gelf_update_move
include		<gelf.h>
declaration	int gelf_update_move(Elf_Data *dest, int ndx, GElf_Move *src)
version		SUNW_1.2
end		

function	gelf_update_syminfo
include		<gelf.h>
declaration	int gelf_update_syminfo(Elf_Data *dest, int ndx, \
			GElf_Syminfo *src)
version		SUNW_1.2
end		

function	gelf_getdyn
include		<gelf.h>
declaration	GElf_Dyn *gelf_getdyn(Elf_Data *src, int ndx, GElf_Dyn *dst)
version		SUNW_1.2
end		

function	gelf_update_dyn
include		<gelf.h>
declaration	int gelf_update_dyn(Elf_Data *dst, int ndx, GElf_Dyn *src)
version		SUNW_1.2
end		

function	gelf_getrela
include		<gelf.h>
declaration	GElf_Rela *gelf_getrela(Elf_Data *src, int ndx, GElf_Rela *dst)
version		SUNW_1.2
end		

function	gelf_update_rela
include		<gelf.h>
declaration	int gelf_update_rela(Elf_Data *dst, int ndx, GElf_Rela *src)
version		SUNW_1.2
end		

function	gelf_getrel
include		<gelf.h>
declaration	GElf_Rel *gelf_getrel(Elf_Data *src, int ndx, GElf_Rel *dst)
version		SUNW_1.2
end		

function	gelf_update_rel
include		<gelf.h>
declaration	int gelf_update_rel(Elf_Data *dst, int ndx, GElf_Rel *src)
version		SUNW_1.2
end		

function	gelf_getcap
include		<gelf.h>
declaration	GElf_Cap *gelf_getcap(Elf_Data *dst, int ndx, GElf_Cap *src)
version		SUNW_1.5
end

function	gelf_update_cap
include		<gelf.h>
declaration	int gelf_update_cap(Elf_Data *dst, int ndx, GElf_Cap *src)
version		SUNW_1.5
end
