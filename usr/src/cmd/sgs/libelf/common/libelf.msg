#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
#ident	"%Z%%M%	%I%	%E% SMI"


@ _START_

# Message file for cmd/sgs/libelf.

@ MSG_ID_LIBELF


# Null Error

@ EINF_NULLERROR	"Elf error 0"


# BUG	bug	Internal error

@ EBUG_COOKSTAT		"Internal error: cook status"
@ EBUG_COOKTYPE		"Internal error: cook data type"
@ EBUG_SCNLIST		"Internal error: broken section list"
@ EBUG_THRDKEY		"Internal error: thr_keycreate() failed. \
			 Unable to allocate error buffer"
@ EBUG_THRDSET		"Internal error: thr_setspecific failed. \
			 Unable to create TSD for error message."


# FMT	fmt	Format error

@ EFMT_ARFMAG		"Format error: archive fmag"
@ EFMT_ARHDRSZ		"Format error: archive header truncated"
@ EFMT_ARMEMSZ		"Format error: archive member truncated"
@ EFMT_ARSYM		"Format error: archive symtab truncated"
@ EFMT_ARSYMSTR		"Format error: archive symtab strings"
@ EFMT_ARSYMSZ		"Format error: archive symtab size"
@ EFMT_DATA		"Format error: data region truncated"
@ EFMT_EHDRSZ		"Format error: ehdr size"
@ EFMT_ENTSZ		"Format error: shdr entry size"
@ EFMT_PHDRSZ		"Format error: phdr entry size"
@ EFMT_PHTAB		"Format error: phdr table truncated"
@ EFMT_SCNSZ		"Format error: section sh_size too small for data"
@ EFMT_SHDRSZ		"Format error: shdr entry size"
@ EFMT_SHTAB		"Format error: shdr table truncated"
@ EFMT_VER2		"Format error: ehdr EI_VERSION/e_version mismatch"
@ EFMT_VM		"Format error: reference outside file"
@ EFMT_FBIG_CLASS32	"Format error: file size exceeds 4GB 32-bit limit"
@ EFMT_FBIG_LARGEFILE	"Format error: file size exceeds 2GB limit of 32-bit \
			 linker. 64-bit linker is recommended."

@ EFMT_ARSTRNM		"Format error: archive strtab name"
@ EFMT_ARUNKNM		"Format error: archive special name unknown"

# IO	io	I/O error

@ EIO_FBIG		"I/O error: file too big for memory"
@ EIO_FSZ		"I/O error: get file size"
@ EIO_READ		"I/O error: raw read"
@ EIO_SEEK		"I/O error: seek"
@ EIO_SYNC		"I/O error: output msync"
@ EIO_VM		"I/O error: region read"
@ EIO_WRITE		"I/O error: output write"


# MEM	mem	Memory error

@ EMEM_ARMEM		"Memory allocation error: archive member header"
@ EMEM_ARSTR		"Memory allocation error: archive long file name \
			 strings"
@ EMEM_ARSYM		"Memory allocation error: archive symtab"
@ EMEM_DATA		"Memory allocation error: section data"
@ EMEM_DNODE		"Memory allocation error: data node"
@ EMEM_EHDR		"Memory allocation error: ehdr"
@ EMEM_ELF		"Memory allocation error: elf descriptor"
@ EMEM_OUT		"Memory allocation error: output file space"
@ EMEM_PHDR		"Memory allocation error: phdr table"
@ EMEM_SCN		"Memory allocation error: scn descriptors"
@ EMEM_SHDR		"Memory allocation error: shdr table"
@ EMEM_SNODE		"Memory allocation error: section node"
@ EMEM_VM		"Memory allocation error: vm stats"
@ EMEM_ERRMSG		"Memory allocation error: during errmsg generation"


# REQ	req	Request error

@ EREQ_AR		"Request error: not archive"
@ EREQ_ARMEMFD		"Request error: archive/member fildes mismatch"
@ EREQ_ARRDWR		"Request error: archive/member begin() for writing"
@ EREQ_BEGIN		"Request error: begin() ELF_C_..."
@ EREQ_CLASS		"Request error: class file/memory mismatch"
@ EREQ_CNTLCMD		"Request error: cntl() ELF_C_..."
@ EREQ_CNTLWRT		"Request error: cntl() ELF_C_FD... on output file"
@ EREQ_DATA		"Request error: data/scn mismatch"
@ EREQ_ENCODE		"Request error: unknown data encoding"
@ EREQ_FLAG		"Request error: flag() ELF_C_..."
@ EREQ_NDX		"Request error: no section at index"
@ EREQ_NOFD		"Request error: file descriptor disabled"
@ EREQ_RAND		"Request error: offset out of range"
@ EREQ_RDWR		"Request error: begin() ELF_C_... mismatch with parent"
@ EREQ_SCNNULL		"Request error: can't manipulate null section"
@ EREQ_STROFF		"Request error: string offset out of range"
@ EREQ_STRSCN		"Request error: no string table"
@ EREQ_UPDATE		"Request error: update() ELF_C_..."
@ EREQ_UPDWRT		"Request error: update() for write on read-only file"
@ EREQ_VER		"Request error: unknown version"
@ EREQ_NOWRIMAGE	"Request error: update(WRIMAGE) not performed on parent"

@ EREQ_DSZ		"Request error: destination too small"
@ EREQ_TYPE		"Request error: unknown ELF_T_..."

#  SEQ	seq	Sequence error

@ ESEQ_EHDR		"Sequence error: ehdr not created"
@ ESEQ_VER		"Sequence error: version not set"


@ _END_


# The following strings represent reserved names.  Reference to these strings
# is via the MSG_ORIG() macro, and thus translations are required.

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"


# System error format

@ MSG_FMT_ERR		"%s: %s"
