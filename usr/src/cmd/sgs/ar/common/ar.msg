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

#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

@ _START_

# Message file for cmd/sgs/ar.

@ MSG_ID_AR

@ MSG_USAGE		"usage: ar -d[-SvV] archive file ...\n       \
			 ar -m[-abiSvV] [posname] archive file ...\n       \
			 ar -p[-vV][-sS] archive [file ...]\n       \
			 ar -q[-cuvSV] [-abi] [posname] [file ...]\n       \
			 ar -r[-cuvSV] [-abi] [posname] [file ...]\n       \
			 ar -t[-vV][-sS] archive [file ...]\n       \
			 ar -x[-vV][-sSCT] archive [file ...]\n"

@ MSG_MALLOC		"ar: could not allocate memory: %s\n"
@ MSG_TOOBIG4G		"ar: archive size exceeds capabilities of 32-bit \
			 process\n"

@ MSG_USAGE_01		"ar: one of [drqtpmx] must be specified\n"
@ MSG_USAGE_02		"ar: -%c requires an operand\n"
@ MSG_USAGE_03		"ar: bad option: -%c\n"
@ MSG_USAGE_04		"ar: only one of [drqtpmx] allowed\n"
@ MSG_USAGE_05		"ar: abi not allowed with q\n"
@ MSG_USAGE_06		"ar: %s taken as mandatory 'posname' with keys 'abi'\n"

@ MSG_INTERNAL_01	"ar: internal error: cannot tell whether file is \
			 included in archive or not\n"
@ MSG_INTERNAL_02	"ar: internal header generation error\n"

@ MSG_SYS_OPEN		"ar: cannot open %s: %s\n"
@ MSG_SYS_CLOSE		"ar: cannot close %s: %s\n"
@ MSG_SYS_WRITE		"ar: %s: cannot write: %s\n"
@ MSG_SYS_STAT		"ar: cannot stat %s: %s\n"
@ MSG_SYS_RENAME	"ar: cannot rename %s to %s: %s\n"

@ MSG_NOT_FOUND_AR	"ar: archive %s not found\n"
@ MSG_NOT_FOUND_POSNAM	"ar: posname %s: not found\n"
@ MSG_NOT_FOUND_FILE	"ar: %s not found\n"

@ MSG_ELF_LIB_FILE	"ar: %s caused libelf error: %s\n"
@ MSG_ELF_LIB_AR	"ar: %s(%s) libelf error: %s\n"
@ MSG_ELF_BEGIN_FILE	"ar: cannot elf_begin() %s: %s\n"
@ MSG_ELF_GETDATA_FILE	"ar: %s has bad elf format: %s\n"
@ MSG_ELF_GETDATA_AR	"ar: %s(%s) has bad elf format: %s\n"
@ MSG_ELF_GETSCN_FILE	"ar: %s has no section header or bad elf format: %s\n"
@ MSG_ELF_GETSCN_AR	"ar: %s(%s) has no section header or bad elf \
			 format: %s\n"
@ MSG_ELF_GETSHSTRNDX_FILE "ar: %s has no string table index: %s\n"
@ MSG_ELF_GETSHSTRNDX_AR "ar: %s(%s) has no string table index: %s\n"
@ MSG_ELF_MALARCHIVE	"ar: %s: offset %lld: malformed archive: %s\n"
@ MSG_ELF_RAWFILE	"ar: elf_rawfile() failed: %s\n"
@ MSG_ELF_VERSION	"ar: libelf.a out of date: %s\n"
@ MSG_W_ELF_NODATA_FILE	"ar: %s has no data in section header table\n"
@ MSG_W_ELF_NODATA_AR	"ar: %s(%s) has no data in section header table\n"

@ MSG_BER_MES_CREATE	"ar: creating %s\n"
@ MSG_BER_MES_WRITE	"ar: writing %s\n"

@ MSG_SYMTAB_01		"ar: symbol table entry size is 0\n"
@ MSG_SYMTAB_NOSTR_FILE	"ar: %s has no string table for symbol names\n"
@ MSG_SYMTAB_NOSTR_AR	"ar: %s(%s) has no string table for symbol names\n"
@ MSG_SYMTAB_NODAT_FILE	"ar: %s has no data in string table\n"
@ MSG_SYMTAB_NODAT_AR	"ar: %s(%s) no data in string table\n"
@ MSG_SYMTAB_ZDAT_FILE	"ar: %s has no data in string table: size is 0\n"
@ MSG_SYMTAB_ZDAT_AR	"ar: %s(%s) no data in string table: size is 0\n"


@ MSG_PATHCONF		"ar: -T failed to calculate file name length: %s\n"
@ MSG_LOCALTIME		"ar: don't have enough space to store the date\n"
@ MSG_NOT_ARCHIVE	"ar: %s not in archive format\n"
@ MSG_OVERRIDE_WARN	"ar: %s already exists. Will not be extracted\n"

@ MSG_ERR_LONGSTRTBLSZ	"ar: archive format limit: long name string table \
			 would exceed 4GB\n"
@ MSG_ERR_MEMBER4G	"ar: archive format limit: individual archive \
			 members are limited to 4GB: %s\n"

@ _END_

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_STR_OPTIONS	":a:b:i:vucsrdxtplmqVCTzMS"
@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

@ MSG_STR_EMPTY		""
@ MSG_STR_HYPHEN	"-"
@ MSG_STR_PERIOD	"."
@ MSG_STR_LCR		"r"
@ MSG_STR_SLASH		"/"
@ MSG_STR_DSLASH	"//"
@ MSG_STR_SYM64		"/SYM64/"

# Format for full member header
#	
@ MSG_MH_FORMAT		"%-16s%-12d%-6u%-6u%-8o%-10lld%-2s"

@ MSG_FMT_VERSION	"ar: %s %s\n"
@ MSG_FMT_P_TITLE	"\n<%s>\n\n"
@ MSG_FMT_T_IDSZ	"%6d/%6d%7lld"
@ MSG_FMT_T_DATE	"%b %e %H:%M %Y"
@ MSG_FMT_SPSTRSP	" %s "
@ MSG_FMT_STRNL		"%s\n"
@ MSG_FMT_FILE		"%c - %s\n"
@ MSG_FMT_LLINT		"/%lld"

@ MSG_CMD_SWAP		"/usr/sbin/swap -s"

# Template for use with mktemp()
@ MSG_STR_MKTEMP	"arXXXXXX"
