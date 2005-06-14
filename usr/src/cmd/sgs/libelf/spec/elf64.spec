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
# cmd/sgs/libelf/spec/elf64.spec

function	elf64_checksum
include		<libelf.h>
declaration	long elf64_checksum(Elf *elf)
version		SUNW_1.3
exception	$return == 0
end		

function	elf64_fsize
include		<libelf.h>
declaration	size_t elf64_fsize(Elf_Type type, size_t count, unsigned ver)
version		SUNW_1.2
exception	$return == 0
end		

function	elf64_getehdr
include		<libelf.h>
declaration	Elf64_Ehdr *elf64_getehdr(Elf *elf)
version		SUNW_1.2
exception	$return == NULL
end		

function	elf64_getphdr
include		<libelf.h>
declaration	Elf64_Phdr *elf64_getphdr(Elf *elf)
version		SUNW_1.2
exception	$return == NULL
end		

function	elf64_getshdr
include		<libelf.h>
declaration	Elf64_Shdr *elf64_getshdr(Elf_Scn *scn)
version		SUNW_1.2
exception	$return == NULL
end		

function	elf64_newehdr
include		<libelf.h>
declaration	Elf64_Ehdr *elf64_newehdr(Elf *elf)
version		SUNW_1.2
exception	$return == NULL
end		

function	elf64_newphdr
include		<libelf.h>
declaration	Elf64_Phdr *elf64_newphdr(Elf *elf, size_t count)
version		SUNW_1.2
exception	$return == NULL
end		

function	elf64_xlatetof
include		<libelf.h>
declaration	Elf_Data *elf64_xlatetof(Elf_Data *dst, const Elf_Data *src,\
			unsigned encode)
version		SUNW_1.2
exception	$return == NULL
end		

function	elf64_xlatetom
include		<libelf.h>
declaration	Elf_Data *elf64_xlatetom(Elf_Data *dst, const Elf_Data *src, \
			unsigned encode)
version		SUNW_1.2
exception	$return == NULL
end		

