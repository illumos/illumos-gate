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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sgs/libelf/spec/elf.spec


function	elf_getphnum
include		<libelf.h>
declaration	int elf_getphnum(Elf *elf, size_t *phnum)
version		SUNW_1.6
end		

function	elf_getshnum
include		<libelf.h>
declaration	int elf_getshnum(Elf *elf, size_t *shnum)
version		SUNW_1.4
end		

function	elf_getshstrndx
include		<libelf.h>
declaration	int elf_getshstrndx(Elf *elf, size_t *shstrndx)
version		SUNW_1.4
end		

function	elf_begin
include		<libelf.h>
declaration	Elf *elf_begin(int fildes, Elf_Cmd cmd, Elf *ref)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_end
include		<libelf.h>
declaration	int elf_end(Elf *elf)
version		SUNW_0.7
exception	$return == 0
end

function	elf_memory
include		<libelf.h>
declaration	Elf *elf_memory(char *image, size_t sz)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_next
include		<libelf.h>
declaration	Elf_Cmd elf_next(Elf *elf)
version		SUNW_0.7
exception	$return == ELF_C_NULL
end

function	elf_rand
include		<libelf.h>
declaration	size_t elf_rand(Elf *elf, size_t offset)
version		SUNW_0.7
exception	$return == 0
end

function	elf_cntl
include		<libelf.h>
declaration	int elf_cntl(Elf *elf, Elf_Cmd cmd)
version		SUNW_0.7
exception	$return == -1
end

function	elf_errmsg
include		<libelf.h>
declaration	const char *elf_errmsg (int err)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_errno
include		<libelf.h>
declaration	int elf_errno(void)
version		SUNW_0.7
end

function	elf_fill
include		<libelf.h>
declaration	void elf_fill(int fill)
version		SUNW_0.7
end

function	elf_flagdata
include		<libelf.h>
declaration	unsigned elf_flagdata(Elf_Data *data, Elf_Cmd cmd, \
			unsigned flags)
version		SUNW_0.7
exception	$return == 0
end

function	elf_flagehdr
include		<libelf.h>
declaration	unsigned elf_flagehdr(Elf *elf,	Elf_Cmd cmd, unsigned flags)
version		SUNW_0.7
exception	$return == 0
end

function	elf_flagelf
include		<libelf.h>
declaration	unsigned elf_flagelf(Elf *elf, Elf_Cmd cmd, unsigned flags)
version		SUNW_0.7
exception	$return == 0
end

function	elf_flagphdr
include		<libelf.h>
declaration	unsigned elf_flagphdr(Elf *elf,	Elf_Cmd	cmd, unsigned flags)
version		SUNW_0.7
exception	$return == 0
end

function	elf_flagscn
include		<libelf.h>
declaration	unsigned elf_flagscn(Elf_Scn *scn, Elf_Cmd cmd, unsigned flags)
version		SUNW_0.7
exception	$return == 0
end

function	elf_flagshdr
include		<libelf.h>
declaration	unsigned elf_flagshdr(Elf_Scn *scn, Elf_Cmd cmd, unsigned flags)
version		SUNW_0.7
exception	$return == 0
end

function	elf_getarhdr
include		<libelf.h>
declaration	Elf_Arhdr *elf_getarhdr(Elf *elf)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_getarsym
include		<libelf.h>
declaration	Elf_Arsym *elf_getarsym(Elf *elf, size_t *ptr)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_getbase
include		<libelf.h>
declaration	off_t elf_getbase(Elf *elf)
version		SUNW_0.7
exception	$return == -1
end

function	elf_getdata
include		<libelf.h>
declaration	Elf_Data *elf_getdata(Elf_Scn *scn, Elf_Data *data)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_newdata
include		<libelf.h>
declaration	Elf_Data *elf_newdata(Elf_Scn *scn)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_rawdata
include		<libelf.h>
declaration	Elf_Data *elf_rawdata(Elf_Scn *scn, Elf_Data *data)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_getident
include		<libelf.h>
declaration	char *elf_getident(Elf *elf, size_t *ptr)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_getscn
include		<libelf.h>
declaration	Elf_Scn *elf_getscn(Elf *elf, size_t index)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_ndxscn
include		<libelf.h>
declaration	size_t elf_ndxscn(Elf_Scn *scn)
version		SUNW_0.7
exception	$return == SHN_UNDEF
end

function	elf_newscn
include		<libelf.h>
declaration	Elf_Scn *elf_newscn(Elf *elf)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_nextscn
include		<libelf.h>
declaration	Elf_Scn *elf_nextscn(Elf *elf, Elf_Scn *scn)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_hash
include		<libelf.h>
declaration	unsigned long elf_hash(const char *name)
version		SUNW_0.7
end

function	elf_kind
include		<libelf.h>
declaration	Elf_Kind elf_kind(Elf *elf)
version		SUNW_0.7
exception	$return == ELF_K_NONE
end

function	elf_rawfile
include		<libelf.h>
declaration	char *elf_rawfile(Elf *elf, size_t *ptr)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_strptr
include		<libelf.h>
declaration	char *elf_strptr(Elf *elf, size_t section, size_t offset)
version		SUNW_0.7
exception	$return == NULL
end

function	elf_update
include		<libelf.h>
declaration	off_t elf_update(Elf *elf, Elf_Cmd cmd)
version		SUNW_0.7
exception	$return == -1
end

function	elf_version
include		<libelf.h>
declaration	unsigned elf_version(unsigned ver)
version		SUNW_0.7
end

function	nlist
include		<nlist.h>
declaration	int nlist(const char *filename, struct nlist *nl)
version		SUNW_0.7
exception	$return == -1
end

function	_elf_getxoff
version		SUNWprivate_1.1
end

function	_elf_outsync
version		SUNWprivate_1.1
end

function	elf_demangle
arch		sparc i386
version		SUNWprivate_1.1
end
