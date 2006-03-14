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
# cmd/sgs/libelf/spec/elf32.spec

function	elf32_checksum
include		<libelf.h>
declaration	long elf32_checksum(Elf *elf)
version		SUNW_1.3
exception	$return == 0
end		

function	elf32_fsize
include		<libelf.h>
declaration	size_t elf32_fsize(Elf_Type type, size_t count, unsigned ver)
version		SUNW_0.7
exception	$return == 0
end		

function	elf32_getphdr
include		<libelf.h>
declaration	Elf32_Phdr *elf32_getphdr(Elf *elf)
version		SUNW_0.7
exception	$return == NULL
end		

function	elf32_newphdr
include		<libelf.h>
declaration	Elf32_Phdr *elf32_newphdr(Elf *elf, size_t count)
version		SUNW_0.7
exception	$return == NULL
end		

function	elf32_getshdr
include		<libelf.h>
declaration	Elf32_Shdr *elf32_getshdr(Elf_Scn *scn)
version		SUNW_0.7
exception	$return == NULL
end		

function	elf32_getehdr
include		<libelf.h>
declaration	Elf32_Ehdr *elf32_getehdr(Elf *elf)
version		SUNW_0.7
exception	$return == NULL
end		

function	elf32_newehdr
include		<libelf.h>
declaration	Elf32_Ehdr *elf32_newehdr(Elf *elf)
version		SUNW_0.7
exception	$return == NULL
end		

function	elf32_xlatetof
include		<libelf.h>
declaration	Elf_Data *elf32_xlatetof(Elf_Data *dst, const Elf_Data *src,\
			unsigned encode)
version		SUNW_0.7
exception	$return == NULL
end		

function	elf32_xlatetom
include		<libelf.h>
declaration	Elf_Data *elf32_xlatetom(Elf_Data *dst, const Elf_Data *src, \
			unsigned encode)
version		SUNW_0.7
exception	$return == NULL
end		

