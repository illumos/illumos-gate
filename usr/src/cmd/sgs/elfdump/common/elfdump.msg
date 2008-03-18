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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

@ _START_

# Message file for cmd/sgs/elfdump.

@ MSG_ID_ELFDUMP

# Usage Messages

@ MSG_USAGE_BRIEF	"usage: %s [-cCdegGhHiklmnrSsuvy] [-I index] \
			 [-N name] [-T type] [-p | -w outfile] file...\n"
@ MSG_USAGE_DETAIL1	"\t[-c]\t\tdump section header information\n"
@ MSG_USAGE_DETAIL2	"\t[-C]\t\tdemangle C++ symbol names\n"
@ MSG_USAGE_DETAIL3	"\t[-d]\t\tdump the contents of the .dynamic section\n"
@ MSG_USAGE_DETAIL4	"\t[-e]\t\tdump the elf header\n"
@ MSG_USAGE_DETAIL5	"\t[-g]\t\tdump the contents of the .group sections\n"
@ MSG_USAGE_DETAIL6	"\t[-G]\t\tdump the contents of the .got section\n"
@ MSG_USAGE_DETAIL7	"\t[-h]\t\tdump the contents of the .hash section\n"
@ MSG_USAGE_DETAIL8	"\t[-H]\t\tdump the contents of the .SUNW_hwcap \
			 section\n"
@ MSG_USAGE_DETAIL9	"\t[-i]\t\tdump the contents of the .interp section\n"
@ MSG_USAGE_DETAIL10	"\t[-I index]\tqualify an option with an index\n"
@ MSG_USAGE_DETAIL11	"\t[-l]\t\tdump with no truncated section names\n"
@ MSG_USAGE_DETAIL12	"\t[-k]\t\tcalculate elf checksum\n"
@ MSG_USAGE_DETAIL13	"\t[-m]\t\tdump the contents of the .SUNW_move \
			 section\n"
@ MSG_USAGE_DETAIL14	"\t[-n]\t\tdump the contents of the .note section\n"
@ MSG_USAGE_DETAIL15	"\t[-N name]\tqualify an option with a `name'\n"
@ MSG_USAGE_DETAIL16	"\t[-P]\t\tuse program headers to generate \
			 section headers\n"
@ MSG_USAGE_DETAIL17	"\t[-p]\t\tdump the program headers\n"
@ MSG_USAGE_DETAIL18	"\t[-r]\t\tdump the contents of the relocation \
			 sections\n"
@ MSG_USAGE_DETAIL19	"\t[-S]\t\tdump the contents of the sort index \
			 sections\n"
@ MSG_USAGE_DETAIL20	"\t[-s]\t\tdump the contents of the symbol table \
			 sections\n"
@ MSG_USAGE_DETAIL21	"\t[-T type]\tqualify an option with a section or \
			 program header type\n"
@ MSG_USAGE_DETAIL22	"\t[-u]\t\tdump the contents of a frame unwind \
			 section\n"
@ MSG_USAGE_DETAIL23	"\t[-v]\t\tdump the contents of the version sections\n"
@ MSG_USAGE_DETAIL24	"\t[-w file]\twrite the contents of specified section \
			 to `file'\n"
@ MSG_USAGE_DETAIL25	"\t[-y]\t\tdump the contents of the .SUNW_syminfo \
			 section\n"

# Errors

@ MSG_ERR_BADFILE	"%s: invalid file type\n"
@ MSG_ERR_BADREL1       "%s: bad relocation entry: %s: relocation requires symbol\n"
@ MSG_ERR_NOSHDR	"%s: section headers are not present: synthesizing \
			 from program headers (-P option)\n"
@ MSG_ERR_PNEEDSPH	"%s: file without program headers is incompatible \
			 with -P option\n"
@ MSG_ERR_NOSHSTRSEC	"%s: no header string table section (shstrtab). \
			 header names are not available\n"
@ MSG_ERR_SHSTRNULL	"%s: zero size section header string table \
			 (shstrtab). header names are not available\n"
@ MSG_ERR_FAILURE	"%s: %s failed: %s\n"
@ MSG_ERR_BADSHDRALIGN	"%s: bad section header array alignment\n"
@ MSG_ERR_BADPHDRALIGN	"%s: bad program header array alignment\n"
@ MSG_ERR_BADSHNAME	"%s: section[%d]: invalid sh_name: %lld\n"
@ MSG_ERR_BADSHLINK	"%s: %s: invalid sh_link: %d\n"
@ MSG_ERR_BADSHINFO	"%s: %s: invalid sh_info: %d\n"
@ MSG_ERR_BADSHTYPE	"%s: %s: invalid sh_type: %d\n"
@ MSG_ERR_BADALIGN	"%s: %s: bad sh_offset alignment\n"
@ MSG_ERR_BADSYM2	"%s: %s: index[%d]: bad symbol entry: %s: must be SHN_COMMON or \
			 defined in SHT_NOBITS section\n"
@ MSG_ERR_BADSYM3	"%s: %s: index[%d]: bad symbol entry: %s: must be defined in \
			 a SHF_TLS section\n"
@ MSG_ERR_BADSYM4	"%s: %s: index[%d]: bad symbol entry: %s: must be defined in \
			 a non-SHF_TLS section\n"
@ MSG_ERR_BADSYM5	"%s: %s: index[%d]: bad symbol entry: %s: \
			 invalid shndx: %d\n"
@ MSG_ERR_BADSYM6	"%s: %s: index[%d]: bad symbol entry: %s: section[%d] \
			 size: %#llx: symbol (address %#llx, size %#llx) \
			 lies outside of containing section\n"
@ MSG_ERR_BADSYM7	"%s: %s: index[%d]: suspicious global symbol entry: %s: lies \
			 within local symbol range (index < %lld)\n"
@ MSG_ERR_BADSYM8	"%s: %s: index[%d]: suspicious local symbol entry: %s: lies \
			 within global symbol range (index >= %lld)\n"

@ MSG_ERR_RELBADSYMNDX	"%s: bad symbol reference %d: from relocation \
			 entry: %d\n"
@ MSG_ERR_HSBADSYMNDX	"%s: bad symbol reference %d: from hash entry: %d\n"
@ MSG_ERR_BADSYMXINDEX1	"%s: %s: index[%d]: invalid SHN_XINDEX reference: \
			 SHT_SYMTAB_SHNDX section truncated: no entry for this \
			 symbol\n"
@ MSG_ERR_BADSYMXINDEX2	"%s: %s: index[%d]: invalid SHN_XINDEX reference: \
			 bad SHT_SYMTAB_SHNDX entry: invalid shndx: 0x%x\n"
@ MSG_ERR_BADSYMXINDEX3	"%s: %s: index[%d]: invalid SHN_XINDEX reference: \
			 SHT_SYMTAB_SHNDX section not found\n"

@ MSG_ERR_BADSTOFF	"%s: %s: index[%d]: bad %s offset: 0x%x: max 0x%x\n"
@ MSG_ERR_BADSZ		"%s: %s: zero size or zero entry size information\n"
@ MSG_ERR_BADMINFO	"%s: %s: invalid m_info: 0x%llx\n"
@ MSG_ERR_BADHASH	"%s: %s: bad hash entry: symbol %s: exists in bucket \
			 %d, should be bucket %ld\n"
@ MSG_ERR_NODYNSYM	"%s: %s: associated SHT_DYNSYM section not found\n"
@ MSG_ERR_BADNDXSEC	"%s: %s: unexpected section type associated with \
			 index section: %s\n"
@ MSG_ERR_BADSORTNDX	"%s: %s: sort section has bad symbol index: %d\n"
@ MSG_ERR_BADVER	"%s: %s: index[%d]: version %d is out of range: \
			 version definitions available: 0-%d\n"
@ MSG_ERR_NOTSTRTAB	"%s: section[%d] is not a string table as expected \
			 by section[%d]\n";

@ MSG_ERR_LDYNNOTADJ	"%s: bad dynamic symbol table layout: %s and %s \
			 sections are not adjacent\n"
@ MSG_ERR_SECMEMOVER	"%s: memory overlap between section[%d]: %s: %llx:%llx \
			 and section[%d]: %s: %llx:%llx\n"
@ MSG_ERR_SHDRMEMOVER	"%s: memory overlap between section header table: \
			 %llx:%llx and section[%d]: %s: %llx:%llx\n"
@ MSG_ERR_MULTDYN	"%s: %d dynamic sections seen (1 expected)\n"
@ MSG_ERR_DYNNOBCKSEC	"%s: object lacks %s section required by DT_%s dynamic \
			 entry\n"
@ MSG_ERR_DYNBADADDR	"%s: DT_%s (%#llx) does not match \
			 shdr[%d: %s].sh_addr (%#llx)\n"
@ MSG_ERR_DYNBADSIZE	"%s: DT_%s (%#llx) does not match \
			 shdr[%d: %s].sh_size (%#llx)\n"
@ MSG_ERR_DYNBADENTSIZE	"%s: DT_%s (%#llx) does not match \
			 shdr[%d: %s].sh_entsize (%#llx)\n"

@ MSG_WARN_INVINTERP1	"%s: PT_INTERP header has no associated section\n"
@ MSG_WARN_INVINTERP2	"%s: interp section: %s: and PT_INTERP program \
			 header have conflicting size or offsets\n"
@ MSG_WARN_INVCAP1	"%s: PT_SUNWCAP header has no associated section\n"
@ MSG_WARN_INVCAP2	"%s: capabilities section: %s: requires PT_CAP program \
			 header\n"
@ MSG_WARN_INVCAP3	"%s: capabilities section: %s: and PT_CAP program \
			 header have conflicting size or offsets\n"

# Elf Output Messages

@ MSG_ELF_SHDR		"Section Header[%d]:  sh_name: %s"
@ MSG_ELF_PHDR		"Program Header[%d]:"

@ MSG_ELF_SCN_CAP	"Hardware/Software Capabilities Section:  %s"
@ MSG_ELF_SCN_INTERP	"Interpreter Section:  %s"
@ MSG_ELF_SCN_VERDEF	"Version Definition Section:  %s"
@ MSG_ELF_SCN_VERNEED	"Version Needed Section:  %s"
@ MSG_ELF_SCN_SYMTAB	"Symbol Table Section:  %s"
@ MSG_ELF_SCN_RELOC	"Relocation Section:  %s"
@ MSG_ELF_SCN_UNWIND	"Unwind Section: %s"
@ MSG_ELF_SCN_DYNAMIC	"Dynamic Section:  %s"
@ MSG_ELF_SCN_NOTE	"Note Section:  %s"
@ MSG_ELF_SCN_HASH	"Hash Section:  %s"
@ MSG_ELF_SCN_SYMINFO	"Syminfo Section:  %s"
@ MSG_ELF_SCN_GOT	"Global Offset Table Section:  %s"
@ MSG_ELF_SCN_GRP	"Group Section:  %s"
@ MSG_ELF_SCN_MOVE	"Move Section:  %s"
@ MSG_ELF_SCN_SYMSORT1	"Symbol Sort Section:  %s (%s)"
@ MSG_ELF_SCN_SYMSORT2	"Symbol Sort Section:  %s (%s / %s)"

@ MSG_ELF_HASH_BKTS1	"%10.10s  buckets contain %8d symbols"
@ MSG_ELF_HASH_BKTS2	"%10.10s  buckets         %8d symbols (globals)"
@ MSG_ELF_HASH_INFO	"    bucket  symndx      name"
@ MSG_HASH_OVERFLW	"%s: warning: section %s: too many symbols to count, \
			 bucket=%d count=%d"
@ MSG_ELF_ERR_SHDR	"\tunable to obtain section header: shstrtab[%lld]\n"
@ MSG_ELF_ERR_DATA	"\tunable to obtain section data: shstrtab[%lld]\n"
@ MSG_ELF_ERR_SCN	"\tunable to obtain section header: section[%d]\n"
@ MSG_ELF_ERR_SCNDATA	"\tunable to obtain section data: section[%d]\n"
@ MSG_ARCHIVE_SYMTAB	"\nSymbol Table: (archive)"
@ MSG_ARCHIVE_FIELDS	"     index    offset    member name and symbol"

@ MSG_GOT_MULTIPLE	"%s: multiple relocations against \
			 the same GOT entry ndx: %d addr: 0x%llx\n"
@ MSG_GOT_UNEXPECTED	"%s: warning: section %s: section unexpected within \
			 relocatable object\n"

# Miscellaneous clutter

@ MSG_STR_NULL		"(null)"
@ MSG_STR_DEPRECATED	"(deprecated value)"
@ MSG_STR_UNKNOWN	"<unknown>"
@ MSG_STR_SECTION	"%.12s (section)"
@ MSG_STR_L_SECTION	"%s (section)"
@ MSG_STR_CHECKSUM	"elf checksum: 0x%lx"

@ MSG_FMT_SCNNDX	"section[%d]"

@ MSG_ERR_MALLOC	"%s: malloc: %s\n"
@ MSG_ERR_OPEN		"%s: open: %s\n"
@ MSG_ERR_READ		"%s: read: %s\n"
@ MSG_ERR_WRITE		"%s: write: %s\n"
@ MSG_ERR_BAD_T_SHT	"%s: unrecognized section header type: %s\n"
@ MSG_ERR_BAD_T_PT	"%s: unrecognized program header type: %s\n"
@ MSG_ERR_AMBIG_MATCH	"%s: ambiguous use of -I, -N, or -T. Remove \
			 -p option or section selection option(s)\n"

#
# SHT_MOVE messages
#
@ MSG_MOVE_TITLE	"    symndx offset   size repeat stride   \
			 value               with respect to"
@ MSG_MOVE_ENTRY	"%10.10s %6lld %6d %6d %6d %#18.18llx  %s"

#
# SHT_GROUP messages
#
@ MSG_GRP_TITLE		"     index    flags / section         signature symbol"
@ MSG_GRP_SIGNATURE	"       [0]   %-24s %s"
@ MSG_GRP_INVALSCN	"<invalid section>"

#
# SHT_NOTE messages
#
@ MSG_NOTE_BADDATASZ	"%s: %s: note header exceeds section size. \
			 offset: 0x%x\n"
@ MSG_NOTE_BADNMSZ	"%s: %s: note name value exceeds section size. \
			 offset: 0x%x namesize: 0x%x\n"
@ MSG_NOTE_BADDESZ	"%s: %s: note data size exceeds section size. \
			 offset: 0x%x datasize: 0x%x\n"

@ _END_

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_STR_OSQBRKT	"["
@ MSG_STR_CSQBRKT	"]"

@ MSG_GRP_COMDAT	" COMDAT "
@ MSG_GRP_ENTRY		"%10.10s   %s [%lld]\n"
@ MSG_GRP_UNKNOWN	" 0x%x "

@ MSG_ELF_GOT		".got"
@ MSG_ELF_INIT		".init"
@ MSG_ELF_FINI		".fini"
@ MSG_ELF_INTERP	".interp"

@ MSG_ELF_GETEHDR	"elf_getehdr"
@ MSG_ELF_GETPHDR	"elf_getphdr"
@ MSG_ELF_GETSHDR	"elf_getshdr"
@ MSG_ELF_GETSCN	"elf_getscn"
@ MSG_ELF_GETDATA	"elf_getdata"
@ MSG_ELF_GETARHDR	"elf_getarhdr"
@ MSG_ELF_GETARSYM	"elf_getarsym"
@ MSG_ELF_RAND		"elf_rand"
@ MSG_ELF_BEGIN		"elf_begin"
@ MSG_ELF_GETPHNUM	"elf_getphnum"
@ MSG_ELF_GETSHNUM	"elf_getshnum"
@ MSG_ELF_GETSHSTRNDX	"elf_getshstrndx"
@ MSG_ELF_XLATETOM	"elf_xlatetom"
@ MSG_ELF_ARSYM		"ARSYM"

@ MSG_GOT_SYM		"_GLOBAL_OFFSET_TABLE_"

@ MSG_STR_OPTIONS	"CcdeGgHhiI:klmN:nPprSsT:uvw:y"

@ MSG_STR_EMPTY		""

@ MSG_FMT_INDENT	"	%s"
@ MSG_FMT_INDEX		" [%lld]"
@ MSG_FMT_INDEX2	"[%d]"
@ MSG_FMT_INTEGER	" %d"
@ MSG_FMT_HASH_INFO	"%10.10s  %-10s  %s"
@ MSG_FMT_ARSYM1	"%10.10s  0x%8.8x  (%s):%s"
@ MSG_FMT_ARSYM2	"%10.10s  0x%8.8x"
@ MSG_FMT_ARNAME	"%s(%s)"
@ MSG_FMT_NLSTR		"\n%s:"
@ MSG_FMT_NLSTRNL	"\n%s:\n"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

# Unwind info

@ MSG_SCN_FRM		".eh_frame"
@ MSG_SCN_FRMHDR	".eh_frame_hdr"

@ MSG_UNW_FRMHDR	"Frame Header:"
@ MSG_UNW_FRMVERS	"  Version: %d"
@ MSG_UNW_FRPTRENC	"  FramePtrEnc: %-20s  FramePtr: 0x%llx"
@ MSG_UNW_FDCNENC	"  FdeCntEnc:   %-20s  FdeCnt: %lld"
@ MSG_UNW_TABENC	"  TableEnc:    %-20s"
@ MSG_UNW_BINSRTAB1	"  Binary Search Table:"
@ MSG_UNW_BINSRTAB2	"      InitialLoc          FdeLoc"
@ MSG_UNW_BINSRTABENT	"    0x%016llx  0x%016llx"
@ MSG_UNW_CIE		"CIE: [0x%08llx]"
@ MSG_UNW_CIELNGTH	" length: 0x%02x cieid: %d"
@ MSG_UNW_CIEVERS	" version: %d  augstring: `%s'"
@ MSG_UNW_CIECALGN	" codealign: 0x%llx  dataalign: %lld  \
			  retaddr: %d"
@ MSG_UNW_CIEAXVAL	" Auxiliary vals:"
@ MSG_UNW_CIEAXSIZ	"   size: %d"
@ MSG_UNW_CIEAXPERS	"   pers: 0x%02x %s 0x%08llx"
@ MSG_UNW_CIEAXCENC	"   cenc: 0x%02x %s"
@ MSG_UNW_CIEAXLSDA	"   lsda: 0x%02x %s"
@ MSG_UNW_CIEAXUNEC	"   Unexpected aug val: %c"
@ MSG_UNW_CIECFI	" CallFrameInstructions:"
@ MSG_UNW_CIEPRE	"   "

@ MSG_UNW_FDE		" FDE: [0x%08llx]"
@ MSG_UNW_FDELNGTH	"    length: 0x%02x  cieptr: 0x%02x"
@ MSG_UNW_FDEINITLOC	"    initloc: 0x%08llx  addrrange: 0x%04llx"
@ MSG_UNW_FDEAXVAL	"   Auxiliary vals:"
@ MSG_UNW_FDEAXSIZE	"      size: 0x%llx"
@ MSG_UNW_FDEAXLSDA	"    lsda: 0x%llx"
@ MSG_UNW_FDECFI	"    CallFrameInstructions:"
@ MSG_UNW_FDEPRE	"      "

@ MSG_UNW_TBLENTRY	"0x%02x "

# Note messages

@ MSG_NOTE_TYPE		"    type   %#x"
@ MSG_NOTE_NAMESZ	"    namesz %#x:"
@ MSG_NOTE_DESCSZ	"    descsz %#x:"
@ MSG_NOTE_DESC		"      desc[%d]\t%s"
@ MSG_NOTE_TOK		"%2.2x "

# Names of fake sections generated from program header data
@ MSG_PHDRNAM_CAP		".SUNW_cap(phdr)"
@ MSG_PHDRNAM_DYN		".dynamic(phdr)"
@ MSG_PHDRNAM_DYNSTR		".dynstr(phdr)"
@ MSG_PHDRNAM_DYNSYM		".dynsym(phdr)"
@ MSG_PHDRNAM_FINIARR		".finiarray(phdr)"
@ MSG_PHDRNAM_HASH		".hash(phdr)"
@ MSG_PHDRNAM_INITARR		".initarray(phdr)"
@ MSG_PHDRNAM_INTERP		".interp(phdr)"
@ MSG_PHDRNAM_LDYNSYM		".SUNW_ldynsym(phdr)"
@ MSG_PHDRNAM_MOVE		".move(phdr)"
@ MSG_PHDRNAM_NOTE		".note(phdr)"
@ MSG_PHDRNAM_PREINITARR	".preinitarray(phdr)"
@ MSG_PHDRNAM_REL		".rel(phdr)"
@ MSG_PHDRNAM_RELA		".rela(phdr)"
@ MSG_PHDRNAM_SYMINFO		".syminfo(phdr)"
@ MSG_PHDRNAM_SYMSORT		".SUNW_symsort(phdr)"
@ MSG_PHDRNAM_TLSSORT		".SUNW_tlssort(phdr)"
@ MSG_PHDRNAM_UNWIND		".eh_frame_hdr(phdr)"
@ MSG_PHDRNAM_VER		".SUNW_version(phdr)"


# Names of sh_type SHT_* type constants

@ MSG_SHT_NULL			"SHT_NULL"		# 0
@ MSG_SHT_NULL_ALT1		"null"
@ MSG_SHT_PROGBITS		"SHT_PROGBITS"		# 1
@ MSG_SHT_PROGBITS_ALT1		"progbits"
@ MSG_SHT_SYMTAB		"SHT_SYMTAB"		# 2
@ MSG_SHT_SYMTAB_ALT1		"symtab"
@ MSG_SHT_STRTAB		"SHT_STRTAB"		# 3
@ MSG_SHT_STRTAB_ALT1		"strtab"
@ MSG_SHT_RELA			"SHT_RELA"		# 4
@ MSG_SHT_RELA_ALT1		"rela"
@ MSG_SHT_HASH			"SHT_HASH"		# 5
@ MSG_SHT_HASH_ALT1		"hash"
@ MSG_SHT_DYNAMIC		"SHT_DYNAMIC"		# 6
@ MSG_SHT_DYNAMIC_ALT1		"dynamic"
@ MSG_SHT_NOTE			"SHT_NOTE"		# 7
@ MSG_SHT_NOTE_ALT1		"note"
@ MSG_SHT_NOBITS		"SHT_NOBITS"		# 8
@ MSG_SHT_NOBITS_ALT1		"nobits"
@ MSG_SHT_REL			"SHT_REL"		# 9
@ MSG_SHT_REL_ALT1		"rel"
@ MSG_SHT_SHLIB			"SHT_SHLIB"		# 10
@ MSG_SHT_SHLIB_ALT1		"shlib"
@ MSG_SHT_DYNSYM		"SHT_DYNSYM"		# 11
@ MSG_SHT_DYNSYM_ALT1		"dynsym"
@ MSG_SHT_INIT_ARRAY		"SHT_INIT_ARRAY"	# 14
@ MSG_SHT_INIT_ARRAY_ALT1	"init_array"
@ MSG_SHT_FINI_ARRAY		"SHT_FINI_ARRAY"	# 15
@ MSG_SHT_FINI_ARRAY_ALT1	"fini_array"
@ MSG_SHT_PREINIT_ARRAY		"SHT_PREINIT_ARRAY"	# 16
@ MSG_SHT_PREINIT_ARRAY_ALT1	"preinit_ARRAY"
@ MSG_SHT_GROUP			"SHT_GROUP"		# 17
@ MSG_SHT_GROUP_ALT1		"group"
@ MSG_SHT_SYMTAB_SHNDX		"SHT_SYMTAB_SHNDX"	# 18
@ MSG_SHT_SYMTAB_SHNDX_ALT1	"symtab_shndx"
@ MSG_SHT_SUNW_SYMSORT		"SHT_SUNW_symsort"	# 0x6ffffff1
@ MSG_SHT_SUNW_SYMSORT_ALT1	"sunw_symsort"
@ MSG_SHT_SUNW_TLSSORT		"SHT_SUNW_tlssort"	# 0x6ffffff2
@ MSG_SHT_SUNW_TLSSORT_ALT1	"sunw_tlssort"
@ MSG_SHT_SUNW_LDYNSYM		"SHT_SUNW_LDYNSYM"	# 0x6ffffff3
@ MSG_SHT_SUNW_LDYNSYM_ALT1	"sunw_ldynsym"
@ MSG_SHT_SUNW_DOF		"SHT_SUNW_dof"		# 0x6ffffff4
@ MSG_SHT_SUNW_DOF_ALT1		"sunw_dof"
@ MSG_SHT_SUNW_CAP		"SHT_SUNW_cap"		# 0x6ffffff5
@ MSG_SHT_SUNW_CAP_ALT1		"sunw_cap"
@ MSG_SHT_SUNW_SIGNATURE	"SHT_SUNW_SIGNATURE"	# 0x6ffffff6
@ MSG_SHT_SUNW_SIGNATURE_ALT1	"sunw_signature"
@ MSG_SHT_SUNW_ANNOTATE		"SHT_SUNW_ANNOTATE"	# 0x6ffffff7
@ MSG_SHT_SUNW_ANNOTATE_ALT1	"sunw_annotate"
@ MSG_SHT_SUNW_DEBUGSTR		"SHT_SUNW_DEBUGSTR"	# 0x6ffffff8
@ MSG_SHT_SUNW_DEBUGSTR_ALT1	"sunw_debugstr"
@ MSG_SHT_SUNW_DEBUG		"SHT_SUNW_DEBUG"	# 0x6ffffff9
@ MSG_SHT_SUNW_DEBUG_ALT1	"sunw_debug"
@ MSG_SHT_SUNW_MOVE		"SHT_SUNW_move"		# 0x6ffffffa
@ MSG_SHT_SUNW_MOVE_ALT1	"sunw_move"
@ MSG_SHT_SUNW_COMDAT		"SHT_SUNW_COMDAT"	# 0x6ffffffb
@ MSG_SHT_SUNW_COMDAT_ALT1	"sunw_comdat"
@ MSG_SHT_SUNW_SYMINFO		"SHT_SUNW_syminfo"	# 0x6ffffffc
@ MSG_SHT_SUNW_SYMINFO_ALT1	"sunw_syminfo"
@ MSG_SHT_SUNW_VERDEF		"SHT_SUNW_verdef"	# 0x6ffffffd
@ MSG_SHT_SUNW_VERDEF_ALT1	"sunw_verdef"
@ MSG_SHT_GNU_VERDEF		"SHT_GNU_verdef"	# 0x6ffffffd
@ MSG_SHT_GNU_VERDEF_ALT1	"gnu_verdef"
@ MSG_SHT_SUNW_VERNEED		"SHT_SUNW_verneed"	# 0x6ffffffe
@ MSG_SHT_SUNW_VERNEED_ALT1	"sunw_verneed"
@ MSG_SHT_GNU_VERNEED		"SHT_GNU_verneed"	# 0x6ffffffe
@ MSG_SHT_GNU_VERNEED_ALT1	"gnu_verneed"
@ MSG_SHT_SUNW_VERSYM		"SHT_SUNW_versym"	# 0x6fffffff
@ MSG_SHT_SUNW_VERSYM_ALT1	"sunw_versym"
@ MSG_SHT_GNU_VERSYM		"SHT_GNU_versym"	# 0x6fffffff
@ MSG_SHT_GNU_VERSYM_ALT1	"gnu_versym"
@ MSG_SHT_SPARC_GOTDATA		"SHT_SPARC_GOTDATA"	# 0x7000000
@ MSG_SHT_SPARC_GOTDATA_ALT1	"sparc_gotdata"
@ MSG_SHT_AMD64_UNWIND		"SHT_AMD64_UNWIND"	# 0x7000000
@ MSG_SHT_AMD64_UNWIND_ALT1	"amd64_unwind"


# Program header PT_ segment types

@ MSG_PT_NULL			"PT_NULL"		# 0
@ MSG_PT_NULL_ALT1		"null"
@ MSG_PT_LOAD			"PT_LOAD"		# 1
@ MSG_PT_LOAD_ALT1		"load"
@ MSG_PT_DYNAMIC		"PT_DYNAMIC"		# 2
@ MSG_PT_DYNAMIC_ALT1		"dynamic"
@ MSG_PT_INTERP			"PT_INTERP"		# 3
@ MSG_PT_INTERP_ALT1		"interp"
@ MSG_PT_NOTE			"PT_NOTE"		# 4
@ MSG_PT_NOTE_ALT1		"note"
@ MSG_PT_SHLIB			"PT_SHLIB"		# 5
@ MSG_PT_SHLIB_ALT1		"shlib"
@ MSG_PT_PHDR			"PT_PHDR"		# 6
@ MSG_PT_PHDR_ALT1		"phdr"
@ MSG_PT_TLS			"PT_TLS"		# 7
@ MSG_PT_TLS_ALT1		"tls"
@ MSG_PT_SUNW_UNWIND		"PT_SUNW_UNWIND"	# 0x6464e550
@ MSG_PT_SUNW_UNWIND_ALT1	"sunw_unwind"
@ MSG_PT_SUNWBSS		"PT_SUNWBSS"		# 0x6ffffffa
@ MSG_PT_SUNWBSS_ALT1		"sunwbss"
@ MSG_PT_SUNWSTACK		"PT_SUNWSTACK"		# 0x6ffffffb
@ MSG_PT_SUNWSTACK_ALT1		"sunwstack"
@ MSG_PT_SUNWDTRACE		"PT_SUNWDTRACE"		# 0x6ffffffc
@ MSG_PT_SUNWDTRACE_ALT1	"sunwdtrace"
@ MSG_PT_SUNWCAP		"PT_SUNWCAP"		# 0x6ffffffd
@ MSG_PT_SUNWCAP_ALT1		"sunwcap"
