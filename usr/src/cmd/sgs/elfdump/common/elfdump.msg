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
# Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
#

@ _START_

# Message file for cmd/sgs/elfdump.

@ MSG_ID_ELFDUMP

# Usage Messages

@ MSG_USAGE_BRIEF	"usage: %s [-cCdegGhHiklmnrSsuvy] [-I index] \
			 [-N name] [-O osabi] [-T type] [-p | -w outfile] \
			 file...\n"
@ MSG_USAGE_DETAIL1	"\t[-c]\t\tdump section header information\n"
@ MSG_USAGE_DETAIL2	"\t[-C]\t\tdemangle C++ symbol names\n"
@ MSG_USAGE_DETAIL3	"\t[-d]\t\tdump the contents of the .dynamic section\n"
@ MSG_USAGE_DETAIL4	"\t[-e]\t\tdump the elf header\n"
@ MSG_USAGE_DETAIL5	"\t[-g]\t\tdump the contents of the .group sections\n"
@ MSG_USAGE_DETAIL6	"\t[-G]\t\tdump the contents of the .got section\n"
@ MSG_USAGE_DETAIL7	"\t[-h]\t\tdump the contents of the .hash section\n"
@ MSG_USAGE_DETAIL8	"\t[-H]\t\tdump the contents of the .SUNW_cap section\n"
@ MSG_USAGE_DETAIL9	"\t[-i]\t\tdump the contents of the .interp section\n"
@ MSG_USAGE_DETAIL10	"\t[-I index]\tqualify an option with an index\n"
@ MSG_USAGE_DETAIL11	"\t[-l]\t\tdump with no truncated section names\n"
@ MSG_USAGE_DETAIL12	"\t[-k]\t\tcalculate elf checksum\n"
@ MSG_USAGE_DETAIL13	"\t[-m]\t\tdump the contents of the .SUNW_move \
			 section\n"
@ MSG_USAGE_DETAIL14	"\t[-n]\t\tdump the contents of the .note section\n"
@ MSG_USAGE_DETAIL15	"\t[-N name]\tqualify an option with a `name'\n"
@ MSG_USAGE_DETAIL16	"\t[-O osabi]\tuse given osabi to interpret object\n"
@ MSG_USAGE_DETAIL17	"\t[-P]\t\tuse program headers to generate \
			 section headers\n"
@ MSG_USAGE_DETAIL18	"\t[-p]\t\tdump the program headers\n"
@ MSG_USAGE_DETAIL19	"\t[-r]\t\tdump the contents of the relocation \
			 sections\n"
@ MSG_USAGE_DETAIL20	"\t[-S]\t\tdump the contents of the sort index \
			 sections\n"
@ MSG_USAGE_DETAIL21	"\t[-s]\t\tdump the contents of the symbol table \
			 sections\n"
@ MSG_USAGE_DETAIL22	"\t[-T type]\tqualify an option with a section or \
			 program header type\n"
@ MSG_USAGE_DETAIL23	"\t[-u]\t\tdump the contents of a frame unwind \
			 section\n"
@ MSG_USAGE_DETAIL24	"\t[-v]\t\tdump the contents of the version sections\n"
@ MSG_USAGE_DETAIL25	"\t[-w file]\twrite the contents of specified section \
			 to `file'\n"
@ MSG_USAGE_DETAIL26	"\t[-y]\t\tdump the contents of the .SUNW_syminfo \
			 section\n"

# Errors

@ MSG_ERR_BADFILE	"%s: invalid file type\n"
@ MSG_ERR_BADREL1	"%s: bad relocation entry: %s: relocation requires \
			 symbol\n"
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
@ MSG_ERR_BADSYM2	"%s: %s: index[%d]: bad symbol entry: %s: must be \
			 SHN_COMMON or defined in SHT_NOBITS section\n"
@ MSG_ERR_BADSYM3	"%s: %s: index[%d]: bad symbol entry: %s: must be \
			 defined in a SHF_TLS section\n"
@ MSG_ERR_BADSYM4	"%s: %s: index[%d]: bad symbol entry: %s: must be \
			 defined in a non-SHF_TLS section\n"
@ MSG_ERR_BADSYM5	"%s: %s: index[%d]: bad symbol entry: %s: \
			 invalid shndx: %d\n"
@ MSG_ERR_BADSYM6	"%s: %s: index[%d]: bad symbol entry: %s: section[%d] \
			 size: %#llx: symbol (address %#llx, size %#llx) \
			 lies outside of containing section\n"
@ MSG_ERR_BADSYM7	"%s: %s: index[%d]: suspicious global symbol entry: \
			 %s: lies within local symbol range (index < %lld)\n"
@ MSG_ERR_BADSYM8	"%s: %s: index[%d]: suspicious local symbol entry: \
			 %s: lies within global symbol range (index >= %lld)\n"

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
@ MSG_ERR_BADSYMNDX	"%s: %s: bad symbol index: %d\n"
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
@ MSG_ERR_DYNNOBCKSEC	"%s: object lacks %s section required by %s dynamic \
			 entry\n"
@ MSG_ERR_DYNBADADDR	"%s: %s (%#llx) does not match \
			 shdr[%d: %s].sh_addr (%#llx)\n"
@ MSG_ERR_DYNBADSIZE	"%s: %s (%#llx) does not match \
			 shdr[%d: %s].sh_size (%#llx)\n"
@ MSG_ERR_DYNBADENTSIZE	"%s: %s (%#llx) does not match \
			 shdr[%d: %s].sh_entsize (%#llx)\n"
@ MSG_ERR_DYNSYMVAL	"%s: %s: symbol value does not match \
			 %s entry: %s: value: %#llx\n"
@ MSG_ERR_MALSTR	"%s: %s: malformed string table, initial or final \
			 byte\n"
@ MSG_ERR_MULTEHFRMHDR	"%s: [%d: %s] multiple .eh_frame_hdr sections seen \
			 (1 expected)\n"
@ MSG_ERR_BADEHFRMPTR	"%s: section[%d: %s] FramePtr (%#llx) does not match \
			 shdr[%d: %s].sh_addr (%#llx)\n"
@ MSG_ERR_BADSORT	"%s: %s: index[%d]: invalid sort order\n"
@ MSG_ERR_BADSIDYNNDX	"%s: [%d: %s][%d]: dynamic section index out of \
			 range (0 - %d): %d\n";
@ MSG_ERR_BADSIDYNTAG	"%s: [%d: %s][%d]: dynamic element \
			 [%d: %s][%d] should have type %s: %s\n";
@ MSG_ERR_BADCIEFDELEN	"%s: %s: invalid CIE/FDE length: %#llx at %#llx\n"                         


@ MSG_WARN_INVINTERP1	"%s: PT_INTERP header has no associated section\n"
@ MSG_WARN_INVINTERP2	"%s: interp section: %s: and PT_INTERP program \
			 header have conflicting size or offsets\n"
@ MSG_WARN_INVCAP1	"%s: PT_SUNWCAP header has no associated section\n"
@ MSG_WARN_INVCAP2	"%s: capabilities section[%d]: %s: requires PT_CAP \
			 program header\n"
@ MSG_WARN_INVCAP3	"%s: capabilities section[%d]: %s: and PT_CAP program \
			 header have conflicting size or offsets\n"
@ MSG_WARN_INVCAP4	"%s: capabilities section[%d]: %s: requires string \
			 table: invalid sh_info: %d\n";
@ MSG_WARN_INADDR32SF1	"%s: capabilities section %s: software capability \
			 ADDR32: is ineffective within a 32-bit object\n"
@ MSG_WARN_MULTEHFRM	"%s: section[%d: %s]: %s object has multiple \
			.eh_frame sections\n"

@ MSG_INFO_LINUXOSABI	"%s: %s object has Linux .note.ABI-tag section. \
			Assuming %s\n"

@ MSG_ERR_DWOVRFLW	"%s: %s: encoded DWARF data exceeds section size\n"
@ MSG_ERR_DWBADENC	"%s: %s: bad DWARF encoding: %#x\n"
@ MSG_ERR_DWNOCIE	"%s: %s: no CIE prior to FDE\n"

# exception_range_entry table entries.
# TRANSLATION_NOTE - the following entries provide for a series of one or more
# standard 32-bit and 64-bit .exception_ranges table entries that align with
# the initial title.

@ MSG_EXR_TITLE_32	"     index    offset     ret_addr   \
			 length     handler    type_blk"
@ MSG_EXR_ENTRY_32	"%10.10s  0x%8.8llx 0x%8.8llx 0x%8.8llx 0x%8.8llx \
			 0x%8.8llx"
@ MSG_EXR_TITLE_64	"     index    offset             ret_addr           \
			 length             handler            type_blk"
@ MSG_EXR_ENTRY_64	"%10.10s  0x%16.16llx 0x%16.16llx 0x%16.16llx \
			 0x%16.16llx 0x%16.16llx"

# Elf Output Messages

@ MSG_ELF_SHDR		"Section Header[%d]:  sh_name: %s"
@ MSG_ELF_PHDR		"Program Header[%d]:"

@ MSG_ELF_SCN_CAP	"Capabilities Section:  %s"
@ MSG_ELF_SCN_CAPCHAIN	"Capabilities Chain Section:  %s"
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

@ MSG_OBJ_CAP_TITLE	" Object Capabilities:"
@ MSG_SYM_CAP_TITLE	" Symbol Capabilities:"
@ MSG_CAPINFO_ENTRIES	"  Symbols:"
@ MSG_CAPCHAIN_TITLE	" Capabilities family: %s"
@ MSG_CAPCHAIN_ENTRY	"  chainndx  symndx      name"
@ MSG_ERR_INVCAP	"%s: capabilities section: %s: contains symbol \
			 capabilities groups, but no capabilities information \
			 section is defined: invalid sh_link: %d\n"
@ MSG_ERR_INVCAPINFO1	"%s: capabilities information section: %s: no symbol \
			 table is defined: invalid sh_link: %d\n"
@ MSG_ERR_INVCAPINFO2	"%s: capabilities information section: %s: no \
			 capabilities chain is defined: invalid sh_info: %d\n"
@ MSG_ERR_INVCAPINFO3	"%s: capabilities information section: %s: index %d: \
			 bad capabilities chain index defined: %d\n"
@ MSG_ERR_CHBADSYMNDX	"%s: bad symbol reference %d: from capability chain: \
			 %s entry: %d\n"

@ MSG_ELF_HASH_BKTS1	"%10.10s  buckets contain %8d symbols"
@ MSG_ELF_HASH_BKTS2	"%10.10s  buckets         %8d symbols (globals)"
@ MSG_ELF_HASH_INFO	"    bucket  symndx      name"
@ MSG_HASH_OVERFLW	"%s: warning: section %s: too many symbols to count, \
			 bucket=%d count=%d"
@ MSG_ELF_ERR_SHDR	"\tunable to obtain section header: shstrtab[%lld]\n"
@ MSG_ELF_ERR_DATA	"\tunable to obtain section data: shstrtab[%lld]\n"
@ MSG_ELF_ERR_SCN	"\tunable to obtain section header: section[%d]\n"
@ MSG_ELF_ERR_SCNDATA	"\tunable to obtain section data: section[%d]\n"
@ MSG_ARCHIVE_SYMTAB_32	"\nSymbol Table: (archive, 32-bit offsets)"
@ MSG_ARCHIVE_SYMTAB_64	"\nSymbol Table: (archive, 64-bit offsets)"
@ MSG_ARCHIVE_FIELDS_32	"     index    offset    member name and symbol"
@ MSG_ARCHIVE_FIELDS_64	"     index    offset            member name and symbol"

@ MSG_GOT_MULTIPLE	"%s: multiple relocations against \
			 the same GOT entry ndx: %d addr: 0x%llx\n"
@ MSG_GOT_UNEXPECTED	"%s: warning: section %s: section unexpected within \
			 relocatable object\n"

# Miscellaneous clutter

@ MSG_STR_NULL		"(null)"
@ MSG_STR_DEPRECATED	"(deprecated value)"
@ MSG_STR_UNKNOWN	"<unknown>"
@ MSG_STR_SECTION	"%s (section)"
@ MSG_STR_CHECKSUM	"elf checksum: 0x%lx"

@ MSG_FMT_SCNNDX	"section[%d]"
@ MSG_FMT_NOTEENTNDX	"  entry [%d]";


@ MSG_ERR_MALLOC	"%s: malloc: %s\n"
@ MSG_ERR_OPEN		"%s: open: %s\n"
@ MSG_ERR_READ		"%s: read: %s\n"
@ MSG_ERR_WRITE		"%s: write: %s\n"
@ MSG_ERR_BAD_T_SHT	"%s: unrecognized section header type: %s\n"
@ MSG_ERR_BAD_T_PT	"%s: unrecognized program header type: %s\n"
@ MSG_ERR_BAD_T_OSABI	"%s: unrecognized operating system ABI: %s\n"
@ MSG_ERR_AMBIG_MATCH	"%s: ambiguous use of -I, -N, or -T. Remove \
			 -p option or section selection option(s)\n"

#
# SHT_MOVE messages
#
@ MSG_MOVE_TITLE	"    symndx     offset   size repeat stride            \
			 value  with respect to"
@ MSG_MOVE_ENTRY	"%10.10s %#10llx %6d %6d %6d %#16llx  %s"

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
@ MSG_NOTE_BADCOREARCH	"%s: elfdump core file note support not available for \
			 architecture: %s\n"
@ MSG_NOTE_BADCOREDATA	"%s: elfdump core file note data truncated or \
			 otherwise malformed\n"
@ MSG_NOTE_BADCORETYPE	"%s: unknown note type %#x\n"

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
@ MSG_ELF_GETPHDRNUM	"elf_getphdrnum"
@ MSG_ELF_GETSHDRNUM	"elf_getshdrnum"
@ MSG_ELF_GETSHDRSTRNDX	"elf_getshdrstrndx"
@ MSG_ELF_XLATETOM	"elf_xlatetom"
@ MSG_ELF_ARSYM		"ARSYM"

@ MSG_SYM_INIT		"_init"
@ MSG_SYM_FINI		"_fini"
@ MSG_SYM_GOT		"_GLOBAL_OFFSET_TABLE_"

@ MSG_STR_OPTIONS	"CcdeGgHhiI:klmN:nO:PprSsT:uvw:y"

@ MSG_STR_8SP		"        "
@ MSG_STR_EMPTY		""
@ MSG_STR_CORE		"CORE"
@ MSG_STR_NOTEABITAG	".note.ABI-tag"
@ MSG_STR_GNU		"GNU"
@ MSG_STR_LOC		"loc"
@ MSG_STR_INITLOC	"initloc"

@ MSG_FMT_INDENT	"	%s"
@ MSG_FMT_INDEX		" [%lld]"
@ MSG_FMT_INDEX2	"[%d]"
@ MSG_FMT_ASRINDEX	"[ asr%d ]"
@ MSG_FMT_INDEXRNG	"[%d-%d]"
@ MSG_FMT_INTEGER	" %d"
@ MSG_FMT_HASH_INFO	"%10.10s  %-10s  %s"
@ MSG_FMT_CHAIN_INFO	"%10.10s  %-10s  %s"
@ MSG_FMT_ARSYM1_32	"%10.10s  0x%8.8llx  (%s):%s"
@ MSG_FMT_ARSYM2_32	"%10.10s  0x%8.8llx"
@ MSG_FMT_ARSYM1_64	"%10.10s  0x%16.16llx  (%s):%s"
@ MSG_FMT_ARSYM2_64	"%10.10s  0x%16.16llx"
@ MSG_FMT_ARNAME	"%s(%s)"
@ MSG_FMT_NLSTR		"\n%s:"
@ MSG_FMT_NLSTRNL	"\n%s:\n"
@ MSG_FMT_SECSYM	"%.*s%s"

@ MSG_HEXDUMP_ROW	"%*s%-*s%s"
@ MSG_HEXDUMP_TOK	"%2.2x"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

# Unwind info

@ MSG_SCN_FRM		".eh_frame"
@ MSG_SCN_FRMHDR	".eh_frame_hdr"
@ MSG_SCN_EXRANGE	".exception_ranges"

@ MSG_UNW_FRMHDR	"Frame Header:"
@ MSG_UNW_FRMVERS	"  Version: %d"
@ MSG_UNW_FRPTRENC	"  FramePtrEnc: %-20s  FramePtr: %#llx"
@ MSG_UNW_FDCNENC	"  FdeCntEnc:   %-20s  FdeCnt: %lld"
@ MSG_UNW_TABENC	"  TableEnc:    %-20s"
@ MSG_UNW_BINSRTAB1	"  Binary Search Table:"
@ MSG_UNW_BINSRTAB2_32	"      InitialLoc    FdeLoc"
@ MSG_UNW_BINSRTAB2_64	"      InitialLoc          FdeLoc"
@ MSG_UNW_BINSRTABENT_32 "    0x%08llx    0x%08llx"
@ MSG_UNW_BINSRTABENT_64 "    0x%016llx  0x%016llx"
@ MSG_UNW_ZEROTERM	"ZERO terminator: [0x00000000]"
@ MSG_UNW_CIE		"CIE: [%#llx]"
@ MSG_UNW_CIELNGTH	" length: 0x%02x cieid: %d"
@ MSG_UNW_CIEVERS	" version: %d  augmentation: `%s'"
@ MSG_UNW_CIECALGN	" codealign: %#llx  dataalign: %lld  \
			  retaddr: %d"
@ MSG_UNW_CIEAXVAL	" Augmentation Data:"
@ MSG_UNW_CIEAXSIZ	"   size: %lld"
@ MSG_UNW_CIEAXPERS	"   personality:"
@ MSG_UNW_CIEAXPERSENC	"       encoding: 0x%02x %s"
@ MSG_UNW_CIEAXPERSRTN	"       routine:  %#08llx"
@ MSG_UNW_CIEAXCENC	"   code pointer encoding: 0x%02x %s"
@ MSG_UNW_CIEAXLSDA	"   lsda encoding: 0x%02x %s"
@ MSG_UNW_CIEAXUNEC	"   Unexpected aug val: %c"
@ MSG_UNW_CIECFI	" CallFrameInstructions:"

@ MSG_UNW_FDE		" FDE: [%#llx]"
@ MSG_UNW_FDELNGTH	"    length:  %#x  cieptr: %#x"
@ MSG_UNW_FDEINITLOC	"    initloc: %#llx  addrrange: %#llx  endloc: %#llx"
@ MSG_UNW_FDEAXVAL	"   Augmentation Data:"
@ MSG_UNW_FDEAXSIZE	"      size: %#llx"
@ MSG_UNW_FDEAXLSDA	"      lsda: %#llx"
@ MSG_UNW_FDECFI	"   CallFrameInstructions:"

# Unwind section Call Frame Instructions. These all start with a leading
# "%*s%s", used to insert leading white space and the opcode name.

@ MSG_CFA_ADV_LOC	"%*s%s: %s + %llu => %#llx"
@ MSG_CFA_CFAOFF	"%*s%s: %s, cfa%+lld"
@ MSG_CFA_CFASET	"%*s%s: cfa=%#llx"
@ MSG_CFA_LLD		"%*s%s: %lld"
@ MSG_CFA_LLU		"%*s%s: %llu"
@ MSG_CFA_REG		"%*s%s: %s"
@ MSG_CFA_REG_OFFLLD	"%*s%s: %s, offset=%lld"
@ MSG_CFA_REG_OFFLLU	"%*s%s: %s, offset=%llu"
@ MSG_CFA_REG_REG	"%*s%s: %s, %s"
@ MSG_CFA_SIMPLE	"%*s%s"
@ MSG_CFA_SIMPLEREP	"%*s%s [%d]"
@ MSG_CFA_EBLK		"%*s%s: expr(%llu bytes)"
@ MSG_CFA_REG_EBLK	"%*s%s: %s, expr(%llu bytes)"

# Architecture specific register name formats

@ MSG_REG_FMT_BASIC	"r%d"
@ MSG_REG_FMT_NAME	"r%d (%s)"


# Note messages

@ MSG_NOTE_TYPE		"    type:   %#x"
@ MSG_NOTE_TYPE_STR	"    type:   %s"
@ MSG_NOTE_NAMESZ	"    namesz: %#x"
@ MSG_NOTE_NAME		"    name:"
@ MSG_NOTE_DESCSZ	"    descsz: %#x"

@ MSG_NOTE_DESC				"    desc:"
@ MSG_CNOTE_DESC_ASRSET_T		"desc: (asrset_t)"
@ MSG_CNOTE_DESC_AUXV_T			"desc: (auxv_t)"
@ MSG_CNOTE_DESC_CORE_CONTENT_T		"desc: (core_content_t)"
@ MSG_CNOTE_DESC_LWPSINFO_T		"desc: (lwpsinfo_t)"
@ MSG_CNOTE_DESC_LWPSTATUS_T		"desc: (lwpstatus_t)"
@ MSG_CNOTE_DESC_PRCRED_T		"desc: (prcred_t)"
@ MSG_CNOTE_DESC_PRIV_IMPL_INFO_T	"desc: (priv_impl_info_t)"
@ MSG_CNOTE_DESC_PRPRIV_T		"desc: (prpriv_t)"
@ MSG_CNOTE_DESC_PRPSINFO_T		"desc: (prpsinfo_t)"
@ MSG_CNOTE_DESC_PRSTATUS_T		"desc: (prstatus_t)"
@ MSG_CNOTE_DESC_PSINFO_T		"desc: (psinfo_t)"
@ MSG_CNOTE_DESC_PSTATUS_T		"desc: (pstatus_t)"
@ MSG_CNOTE_DESC_STRUCT_UTSNAME		"desc: (struct utsname)"
@ MSG_CNOTE_DESC_PRFDINFO_T		"desc: (prfdinfo_t)"


@ MSG_CNOTE_FMT_LINE		"%*s%-*s%s"
@ MSG_CNOTE_FMT_LINE_2UP	"%*s%-*s%-*s%-*s%s"
@ MSG_CNOTE_FMT_D		"%d"
@ MSG_CNOTE_FMT_LLD		"%lld"
@ MSG_CNOTE_FMT_U		"%u"
@ MSG_CNOTE_FMT_LLU		"%llu"
@ MSG_CNOTE_FMT_X		"%#x"
@ MSG_CNOTE_FMT_LLX		"%#llx"
@ MSG_CNOTE_FMT_Z2X		"0x%2.2x"
@ MSG_CNOTE_FMT_Z4X		"0x%4.4x"
@ MSG_CNOTE_FMT_Z8X		"0x%8.8x"
@ MSG_CNOTE_FMT_Z16LLX		"0x%16.16llx"
@ MSG_CNOTE_FMT_TITLE		"%*s%s"
@ MSG_CNOTE_FMT_AUXVLINE	"%*s%10.10s  %-*s  %s"
@ MSG_CNOTE_FMT_PRTPCT		"%u.%u%%"

@ MSG_CNOTE_T_PRIV_FLAGS		"priv_flags:"
@ MSG_CNOTE_T_PRIV_GLOBALINFOSIZE	"priv_globalinfosize:"
@ MSG_CNOTE_T_PRIV_HEADERSIZE		"priv_headersize:"
@ MSG_CNOTE_T_PRIV_INFOSIZE		"priv_infosize:"
@ MSG_CNOTE_T_PRIV_MAX			"priv_max:"
@ MSG_CNOTE_T_PRIV_NSETS		"priv_nsets:"
@ MSG_CNOTE_T_PRIV_SETSIZE		"priv_setsize:"
@ MSG_CNOTE_T_PR_ACTION			"pr_action:"
@ MSG_CNOTE_T_PR_ADDR			"pr_addr:"
@ MSG_CNOTE_T_PR_AGENTID		"pr_agentid:"
@ MSG_CNOTE_T_PR_ALTSTACK		"pr_altstack:"
@ MSG_CNOTE_T_PR_ARGC			"pr_argc:"
@ MSG_CNOTE_T_PR_ARGV			"pr_argv:"
@ MSG_CNOTE_T_PR_ASLWPID		"pr_aslwpid:"
@ MSG_CNOTE_T_PR_BIND			"pr_bind:"
@ MSG_CNOTE_T_PR_BINDPRO		"pr_bindpro:"
@ MSG_CNOTE_T_PR_BINDPSET		"pr_bindpset:"
@ MSG_CNOTE_T_PR_BRKBASE		"pr_brkbase:"
@ MSG_CNOTE_T_PR_BRKSIZE		"pr_brksize:"
@ MSG_CNOTE_T_PR_BYRSSIZE		"pr_byrssize:"
@ MSG_CNOTE_T_PR_BYSIZE			"pr_bysize:"
@ MSG_CNOTE_T_PR_CLNAME			"pr_clname:"
@ MSG_CNOTE_T_PR_CONTRACT		"pr_contract:"
@ MSG_CNOTE_T_PR_CPU			"pr_cpu:"
@ MSG_CNOTE_T_PR_CSTIME			"pr_cstime:"
@ MSG_CNOTE_T_PR_CTIME			"pr_ctime:"
@ MSG_CNOTE_T_PR_CURSIG			"pr_cursig:"
@ MSG_CNOTE_T_PR_CUTIME			"pr_cutime:"
@ MSG_CNOTE_T_PR_DMODEL			"pr_dmodel:"
@ MSG_CNOTE_T_PR_EGID			"pr_egid:"
@ MSG_CNOTE_T_PR_ENVP			"pr_envp:"
@ MSG_CNOTE_T_PR_ERRNO			"pr_errno:"
@ MSG_CNOTE_T_PR_ERRPRIV		"pr_errpriv:"
@ MSG_CNOTE_T_PR_EUID			"pr_euid:"
@ MSG_CNOTE_T_PR_FLAG			"pr_flag:"
@ MSG_CNOTE_T_PR_FLAGS			"pr_flags:"
@ MSG_CNOTE_T_PR_FLTTRACE		"pr_flttrace:"
@ MSG_CNOTE_T_PR_FNAME			"pr_fname:"
@ MSG_CNOTE_T_PR_FPREG			"pr_fpreg:"
@ MSG_CNOTE_T_PR_GID			"pr_gid:"
@ MSG_CNOTE_T_PR_GROUPS			"pr_groups:"
@ MSG_CNOTE_T_PR_INFO			"pr_info:"
@ MSG_CNOTE_T_PR_INFOSIZE		"pr_infosize:"
@ MSG_CNOTE_T_PR_INSTR			"pr_instr:"
@ MSG_CNOTE_T_PR_LGRP			"pr_lgrp:"
@ MSG_CNOTE_T_PR_LTTYDEV		"pr_lttydev:"
@ MSG_CNOTE_T_PR_LWP			"pr_lwp:"
@ MSG_CNOTE_T_PR_LWPHOLD		"pr_lwphold:"
@ MSG_CNOTE_T_PR_LWPID			"pr_lwpid:"
@ MSG_CNOTE_T_PR_LWPPEND		"pr_lwppend:"
@ MSG_CNOTE_T_PR_NAME			"pr_name:"
@ MSG_CNOTE_T_PR_NGROUPS		"pr_ngroups:"
@ MSG_CNOTE_T_PR_NICE			"pr_nice:"
@ MSG_CNOTE_T_PR_NLWP			"pr_nlwp:"
@ MSG_CNOTE_T_PR_NSETS			"pr_nsets:"
@ MSG_CNOTE_T_PR_NSYSARG		"pr_nsysarg:"
@ MSG_CNOTE_T_PR_NZOMB			"pr_nzomb:"
@ MSG_CNOTE_T_PR_OLDCONTEXT		"pr_oldcontext:"
@ MSG_CNOTE_T_PR_OLDPRI			"pr_oldpri:"
@ MSG_CNOTE_T_PR_ONPRO			"pr_onpro:"
@ MSG_CNOTE_T_PR_OTTYDEV		"pr_ottydev:"
@ MSG_CNOTE_T_PR_PCTCPU			"pr_pctcpu:"
@ MSG_CNOTE_T_PR_PCTMEM			"pr_pctmem:"
@ MSG_CNOTE_T_PR_PGID			"pr_pgid:"
@ MSG_CNOTE_T_PR_PGRP			"pr_pgrp:"
@ MSG_CNOTE_T_PR_PID			"pr_pid:"
@ MSG_CNOTE_T_PR_POOLID			"pr_poolid:"
@ MSG_CNOTE_T_PR_PPID			"pr_ppid:"
@ MSG_CNOTE_T_PR_PRI			"pr_pri:"
@ MSG_CNOTE_T_PR_PROCESSOR		"pr_processor:"
@ MSG_CNOTE_T_PR_PROJID			"pr_projid:"
@ MSG_CNOTE_T_PR_PSARGS			"pr_psargs:"
@ MSG_CNOTE_T_PR_REG			"pr_reg:"
@ MSG_CNOTE_T_PR_RGID			"pr_rgid:"
@ MSG_CNOTE_T_PR_RSSIZE			"pr_rssize:"
@ MSG_CNOTE_T_PR_RUID			"pr_ruid:"
@ MSG_CNOTE_T_PR_RVAL1			"pr_rval1:"
@ MSG_CNOTE_T_PR_RVAL2			"pr_rval2:"
@ MSG_CNOTE_T_PR_SETS			"pr_sets:"
@ MSG_CNOTE_T_PR_SETSIZE		"pr_setsize:"
@ MSG_CNOTE_T_PR_SGID			"pr_sgid:"
@ MSG_CNOTE_T_PR_SID			"pr_sid:"
@ MSG_CNOTE_T_PR_SIGHOLD		"pr_sighold:"
@ MSG_CNOTE_T_PR_SIGPEND		"pr_sigpend:"
@ MSG_CNOTE_T_PR_SIGTRACE		"pr_sigtrace:"
@ MSG_CNOTE_T_PR_SIZE			"pr_size:"
@ MSG_CNOTE_T_PR_SNAME			"pr_sname:"
@ MSG_CNOTE_T_PR_START			"pr_start:"
@ MSG_CNOTE_T_PR_STATE			"pr_state:"
@ MSG_CNOTE_T_PR_STIME			"pr_stime:"
@ MSG_CNOTE_T_PR_STKBASE		"pr_stkbase:"
@ MSG_CNOTE_T_PR_STKSIZE		"pr_stksize:"
@ MSG_CNOTE_T_PR_STYPE			"pr_stype:"
@ MSG_CNOTE_T_PR_SUID			"pr_suid:"
@ MSG_CNOTE_T_PR_SYSARG			"pr_sysarg:"
@ MSG_CNOTE_T_PR_SYSCALL		"pr_syscall:"
@ MSG_CNOTE_T_PR_SYSENTRY		"pr_sysentry:"
@ MSG_CNOTE_T_PR_SYSEXIT		"pr_sysexit:"
@ MSG_CNOTE_T_PR_TASKID			"pr_taskid:"
@ MSG_CNOTE_T_PR_TIME			"pr_time:"
@ MSG_CNOTE_T_PR_TSTAMP			"pr_tstamp:"
@ MSG_CNOTE_T_PR_TTYDEV			"pr_ttydev:"
@ MSG_CNOTE_T_PR_UID			"pr_uid:"
@ MSG_CNOTE_T_PR_USTACK			"pr_ustack:"
@ MSG_CNOTE_T_PR_UTIME			"pr_utime:"
@ MSG_CNOTE_T_PR_WCHAN			"pr_wchan:"
@ MSG_CNOTE_T_PR_WHAT			"pr_what:"
@ MSG_CNOTE_T_PR_WHO			"pr_who:"
@ MSG_CNOTE_T_PR_WHY			"pr_why:"
@ MSG_CNOTE_T_PR_WSTAT			"pr_wstat:"
@ MSG_CNOTE_T_PR_ZOMB			"pr_zomb:"
@ MSG_CNOTE_T_PR_ZONEID			"pr_zoneid:"
@ MSG_CNOTE_T_SA_FLAGS			"sa_flags:"
@ MSG_CNOTE_T_SA_HANDLER		"sa_handler:"
@ MSG_CNOTE_T_SA_MASK			"sa_mask:"
@ MSG_CNOTE_T_SA_SIGACTION		"sa_sigaction:"
@ MSG_CNOTE_T_SIVAL_INT			"sival_int:"
@ MSG_CNOTE_T_SIVAL_PTR			"sival_ptr:"
@ MSG_CNOTE_T_SI_ADDR			"si_addr:"
@ MSG_CNOTE_T_SI_BAND			"si_band:"
@ MSG_CNOTE_T_SI_CODE			"si_code:"
@ MSG_CNOTE_T_SI_CTID			"si_ctid:"
@ MSG_CNOTE_T_SI_ENTITY			"si_entity"
@ MSG_CNOTE_T_SI_ERRNO			"si_errno:"
@ MSG_CNOTE_T_SI_PID			"si_pid:"
@ MSG_CNOTE_T_SI_SIGNO			"si_signo:"
@ MSG_CNOTE_T_SI_STATUS			"si_status:"
@ MSG_CNOTE_T_SI_UID			"si_uid:"
@ MSG_CNOTE_T_SI_VALUE			"si_value:"
@ MSG_CNOTE_T_SI_ZONEID			"si_zoneid:"
@ MSG_CNOTE_T_SS_FLAGS			"ss_flags:"
@ MSG_CNOTE_T_SS_SIZE			"ss_size:"
@ MSG_CNOTE_T_SS_SP			"ss_sp:"
@ MSG_CNOTE_T_TV_NSEC			"tv_nsec:"
@ MSG_CNOTE_T_TV_SEC			"tv_sec:"
@ MSG_CNOTE_T_UTS_MACHINE		"machine:"
@ MSG_CNOTE_T_UTS_NODENAME		"nodename:"
@ MSG_CNOTE_T_UTS_RELEASE		"release:"
@ MSG_CNOTE_T_UTS_SYSNAME		"sysname:"
@ MSG_CNOTE_T_UTS_VERSION		"version:"
@ MSG_CNOTE_T_PR_FD			"pr_fd:"
@ MSG_CNOTE_T_PR_MODE			"pr_mode:"
@ MSG_CNOTE_T_PR_PATH			"pr_path:"
@ MSG_CNOTE_T_PR_MAJOR			"pr_major:"
@ MSG_CNOTE_T_PR_MINOR			"pr_minor:"
@ MSG_CNOTE_T_PR_RMAJOR			"pr_rmajor:"
@ MSG_CNOTE_T_PR_RMINOR			"pr_rminor:"
@ MSG_CNOTE_T_PR_OFFSET			"pr_offset:"
@ MSG_CNOTE_T_PR_INO			"pr_ino:"
@ MSG_CNOTE_T_PR_FILEFLAGS		"pr_fileflags:"
@ MSG_CNOTE_T_PR_FDFLAGS		"pr_fdflags:"


# Names of fake sections generated from program header data
@ MSG_PHDRNAM_CAP		".SUNW_cap(phdr)"
@ MSG_PHDRNAM_CAPINFO		".SUNW_capinfo(phdr)"
@ MSG_PHDRNAM_CAPCHAIN		".SUNW_capchain(phdr)"
@ MSG_PHDRNAM_DYN		".dynamic(phdr)"
@ MSG_PHDRNAM_DYNSTR		".dynstr(phdr)"
@ MSG_PHDRNAM_DYNSYM		".dynsym(phdr)"
@ MSG_PHDRNAM_FINIARR		".fini_array(phdr)"
@ MSG_PHDRNAM_HASH		".hash(phdr)"
@ MSG_PHDRNAM_INITARR		".init_array(phdr)"
@ MSG_PHDRNAM_INTERP		".interp(phdr)"
@ MSG_PHDRNAM_LDYNSYM		".SUNW_ldynsym(phdr)"
@ MSG_PHDRNAM_MOVE		".move(phdr)"
@ MSG_PHDRNAM_NOTE		".note(phdr)"
@ MSG_PHDRNAM_PREINITARR	".preinit_array(phdr)"
@ MSG_PHDRNAM_REL		".rel(phdr)"
@ MSG_PHDRNAM_RELA		".rela(phdr)"
@ MSG_PHDRNAM_SYMINFO		".syminfo(phdr)"
@ MSG_PHDRNAM_SYMSORT		".SUNW_symsort(phdr)"
@ MSG_PHDRNAM_TLSSORT		".SUNW_tlssort(phdr)"
@ MSG_PHDRNAM_UNWIND		".eh_frame_hdr(phdr)"
@ MSG_PHDRNAM_VER		".SUNW_version(phdr)"
