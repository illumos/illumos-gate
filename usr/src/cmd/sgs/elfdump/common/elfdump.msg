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

@ _START_

# Message file for cmd/sgs/elfdump.

@ MSG_ID_ELFDUMP

# Usage Messages

@ MSG_USAGE_BRIEF	"usage: %s [-cCdegGhHiklmnprsuvy] [-N name] \
			 [-W file] file(s)\n"
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
@ MSG_USAGE_DETAIL9_1	"\t[-l]\t\tdump with no truncated section names\n"
@ MSG_USAGE_DETAIL10	"\t[-k]\t\tcalculate elf checksum\n"
@ MSG_USAGE_DETAIL11	"\t[-m]\t\tdump the contents of the .SUNW_move \
			 section\n"
@ MSG_USAGE_DETAIL12	"\t[-n]\t\tdump the contents of the .note section\n"
@ MSG_USAGE_DETAIL13	"\t[-N name]\tqualify an option with a `name'\n"
@ MSG_USAGE_DETAIL14	"\t[-p]\t\tdump the program headers\n"
@ MSG_USAGE_DETAIL15	"\t[-r]\t\tdump the contents of the relocation \
			 sections\n"
@ MSG_USAGE_DETAIL16	"\t[-s]\t\tdump the contents of the symbol table \
			 sections\n"
@ MSG_USAGE_DETAIL17	"\t[-u]\t\tdump the contents of a frame unwind \
			 section\n"
@ MSG_USAGE_DETAIL18	"\t[-v]\t\tdump the contents of the version sections\n"
@ MSG_USAGE_DETAIL19	"\t[-w file]\twrite the contents of specified section \
			 to `file'\n"
@ MSG_USAGE_DETAIL20	"\t[-y]\t\tdump the contents of the .SUNW_syminfo \
			 section\n"

@ MSG_USAGE_DEMANGLE	"usage: -C option is only meaningful \
			 with other options that display symbol names\n"
@ MSG_USAGE_LONGNAME	"usage: -l option is only meaningful \
			 with other options that display section names\n"

# Errors

@ MSG_ERR_BADFILE	"%s: invalid file type\n"
@ MSG_ERR_BADREL1       "%s: bad relocation entry: %s: relocation requires symbol\n"
@ MSG_ERR_SHSTRNULL	"%s: zero size section header string table (shstrtab)\n"
@ MSG_ERR_FAILURE	"%s: %s failed: %s\n"
@ MSG_ERR_BADSHNAME	"%s: %s: invalid sh_name: %lld\n"
@ MSG_ERR_BADSHLINK	"%s: %s: invalid sh_link: %lld\n"
@ MSG_ERR_BADSHINFO	"%s: %s: invalid sh_info: %lld\n"
@ MSG_ERR_BADSHTYPE	"%s: %s: invalid sh_type: %lld\n"
@ MSG_ERR_BADALIGN	"%s: %s: bad sh_offset alignment\n"
@ MSG_ERR_SIBADCOUNT	"%s: %s: bad syminfo entry: %d\n"
@ MSG_ERR_BADCAP	"%s: %s: bad capabilities entry: %s\n"
@ MSG_ERR_BADSYM	"%s: %s: bad symbol entry: %s\n"
@ MSG_ERR_BADSYM2	"%s: %s: bad symbol entry: %s: must be SHN_COMMON or \
			 defined in SHT_NOBITS section\n"
@ MSG_ERR_BADSYM3	"%s: %s: bad symbol entry: %s: must be defined in \
			 a SHF_TLS section\n"
@ MSG_ERR_BADSYM4	"%s: %s: bad symbol entry: %s: must be defined in \
			 a non-SHF_TLS section\n"
@ MSG_ERR_BADSYM5	"%s: %s: bad symbol entry: %s: invalid shndx: %d\n"
@ MSG_ERR_BADSYM6	"%s: %s: bad symbol entry: %s: section[%d] size: %lld: \
			 is smaller than symbol size: %lld\n"
@ MSG_ERR_BADMOVE	"%s: %s: bad move table entry: %s\n"
@ MSG_ERR_BADREL	"%s: %s: bad relocation table entry: %s\n"
@ MSG_ERR_RELBADSYMNDX	"%s: bad symbol reference from relocation entry: %s\n"
@ MSG_ERR_MVBADSYMNDX	"%s: bad symbol reference from move entry: %s\n"
@ MSG_ERR_HSBADSYMNDX	"%s: bad symbol reference from hash entry: %s\n"
@ MSG_ERR_GRBADSYMNDX	"%s: bad symbol reference from group entry: %s\n"
@ MSG_ERR_BADSYMXINDEX1	"%s: %s: index[%d]: invalid SHN_XINDEX reference: \
			 SHT_SYMTAB_SHNDX section truncated: no entry for this \
			 symbol\n"
@ MSG_ERR_BADSYMXINDEX2	"%s: %s: index[%d]: invalid SHN_XINDEX reference: \
			 bad SHT_SYMTAB_SHNDX entry: invalid shndx: 0x%x\n"
@ MSG_ERR_BADSYMXINDEX3	"%s: %s: index[%d]: invalid SHN_XINDEX reference: \
			 SHT_SYMTAB_SHNDX section not found\n"
@ MSG_ERR_BADSTOFF	"%s: %s: index[%d]: bad %s offset: 0x%llx: max 0x%llx\n"
@ MSG_ERR_BADDYN	"%s: %s: bad index into .dynamic: %d\n"
@ MSG_ERR_BADSZ		"%s: %s: zero size or entry size information\n"
@ MSG_ERR_BADMINFO	"%s: %s: invalid m_info: 0x%llx\n"
@ MSG_ERR_BADHASH	"%s: %s: bad hash entry: symbol %s: exists in bucket \
			 %d, should be bucket %d\n"

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
@ MSG_ELF_SCN_GOT	"Global Offset Table Section:  %s  (%u entries)"

@ MSG_ELF_RELOC_RELA	"\ttype\t\t              offset     addend  section        \
			 with respect to"
@ MSG_ELF_RELOC_REL	"\ttype\t\t              offset             section        \
			 with respect to"
@ MSG_ELF_L_RELOC_RELA	"\ttype\t\t              offset     addend  section/symbol"
@ MSG_ELF_L_RELOC_REL	"\ttype\t\t              offset             section/symbol"
@ MSG_ELF_HASH_BKTS1	"%10.10s  buckets contain %8d symbols"
@ MSG_ELF_HASH_BKTS2	"%10.10s  buckets         %8d symbols (globals)"
@ MSG_ELF_HASH_INFO	"    bucket    symndx    name"
@ MSG_HASH_OVERFLW	"warning: too many symbols to count, bucket=%d count=%d"
@ MSG_ELF_ERR_SHDR	"\tunable to obtain section header: shstrtab[%lld]\n"
@ MSG_ELF_ERR_DATA	"\tunable to obtain section data: shstrtab[%lld]\n"
@ MSG_ELF_ERR_SCN	"\tunable to obtain section header: section[%d]\n"
@ MSG_ELF_ERR_SCNDATA	"\tunable to obtain section data: section[%d]\n"
@ MSG_ARCHIVE_SYMTAB	"\nSymbol Table: (archive)"
@ MSG_ARCHIVE_FIELDS	"     index    offset    member name and symbol"
@ MSG_GOT_MULTIPLE	"%s: multiple relocations against \
			 the same GOT entry ndx: %d addr: 0x%llx\n"



# Miscellaneous clutter

@ MSG_STR_INDEX		"index"
@ MSG_STR_NAME		"name"
@ MSG_STR_NULL		"(null)"
@ MSG_STR_DEPRECATED	"(deprecated value)"
@ MSG_STR_UNKNOWN	"<unknown>"
@ MSG_STR_SECTION	"%.12s (section)"
@ MSG_STR_L_SECTION	"%s (section)"
@ MSG_STR_CHECKSUM	"elf checksum: 0x%lx"

@ MSG_FMT_SCNNDX	"section[%d]"

@ MSG_ERR_MALLOC	"%s: malloc: %s\n"
@ MSG_ERR_OPEN		"%s: open: %s\n"

#
# For Elf{32,64}_Move section
#
@ MSG_MV_TITLE		"Move Section: %s\n\
			 \toffset\tndx\tsize\trepeat\tstride\tvalue\twith \
			 respect to"
@ MSG_MV_ENTRY		"\t0x%llx\t0x%llx\t%d\t%d\t%d\t0x%llx\t%s"


#
# SHT_GROUP messages
#
@ MSG_GRP_NOTSYMTAB	"%s: %s: sh_link[%lld] does not point to .symtab\n"
@ MSG_GRP_BADSYMNDX	"%s: %s: sh_info[%lld] has invalid symbol index\n"
@ MSG_GRP_BADENTSZ	"%s: %s: has invalid sh_entsize: %lld\n"
@ MSG_GRP_LINE1		"\nGroup Section: %s"
@ MSG_GRP_LINE2		"\t[ndx]  Flags/Section		Signature Symbol"
@ MSG_GRP_LINE3		"\t  [0]   %-24s %s"
@ MSG_GRP_INVALSCN	"<invalid section>"

#
# SHT_NOTE messages
#
@ MSG_NOTE_BADDATASIZE	"%s: %s: note header exceeds section size. \
			 offset: 0x%x\n"
@ MSG_NOTE_BADNMSIZE	"%s: %s: note name value exceeds section size. \
			 offset: 0x%x namesize: 0x%x\n"
@ MSG_NOTE_BADDESIZE	"%s: %s: note data size exceeds section size. \
			 offset: 0x%x datasize: 0x%x\n"


@ _END_

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


@ MSG_GRP_COMDAT	" COMDAT"
@ MSG_GRP_FMT1		" 0x%x"
@ MSG_GRP_FMT2		"%13.13s   %s[%d]\n"
@ MSG_GRP_CLOSBRKT	" ]"

@ MSG_ELF_GOT		".got"

@ MSG_ELF_GETEHDR	"elf_getehdr"
@ MSG_ELF_GETPHDR	"elf_getphdr"
@ MSG_ELF_GETSHDR	"elf_getshdr"
@ MSG_ELF_GETSCN	"elf_getscn"
@ MSG_ELF_GETDATA	"elf_getdata"
@ MSG_ELF_GETARHDR	"elf_getarhdr"
@ MSG_ELF_GETARSYM	"elf_getarsym"
@ MSG_ELF_RAND		"elf_rand"
@ MSG_ELF_BEGIN		"elf_begin"
@ MSG_ELF_GETSHNUM	"elf_getshnum"
@ MSG_ELF_GETSHSTRNDX	"elf_getshstrndx"
@ MSG_ELF_ARSYM		"ARSYM"

@ MSG_GOT_SYM		"_GLOBAL_OFFSET_TABLE_"

@ MSG_STR_OPTIONS	"CcdeGgHhiklmN:nprsuvw:y"

@ MSG_STR_EMPTY		""
@ MSG_STR_NL		"\n"

@ MSG_FMT_INDENT	"	%s"
@ MSG_FMT_INDEX		" [%lld]"
@ MSG_FMT_INDEX2	"[%lld]"
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
@ MSG_UNW_FRPTRENC	"  FramePtrEnc: %-16s FramePtr: 0x%llx"
@ MSG_UNW_FDCNENC	"  FdeCntEnc:   %-16s  FdeCnt: %lld"
@ MSG_UNW_TABENC	"  TableEnc:    %-16s"
@ MSG_UNW_BINSRTAB1	"  Binary Search Table:"
@ MSG_UNW_BINSRTAB2	"     InitialLoc         FdeLoc"
@ MSG_UNW_BINSRTABENT	"    0x%012llx     0x%012llx"
@ MSG_UNW_CIE		"CIE: [0x%08llx]"
@ MSG_UNW_CIELNGTH	" length: 0x%02x cieid: %d"
@ MSG_UNW_CIEVERS	" version: %d  augstring: `%s'"
@ MSG_UNW_CIECALGN	" codealign: 0x%llx  dataalign: %lld  \
			  retaddr: %d"
@ MSG_UNW_CIEAUXVAL	" Auxillary vals:"
@ MSG_UNW_CIEAUXSIZE	"   size: %d"
@ MSG_UNW_CIEAUXPERS	"   pers: 0x%02x %s 0x%08llx"
@ MSG_UNW_CIEAUXCENC	"   cenc: 0x%02x %s"
@ MSG_UNW_CIEAUXLSDA	"   lsda: 0x%02x %s"
@ MSG_UNW_CIEAUXUNEC	"   Unexpected aug val: %c"
@ MSG_UNW_CIECFI	" CallFrameInstructions:"
@ MSG_UNW_CIECFI1	"\n    "
@ MSG_UNW_CIECFI2	"0x%02x "

@ MSG_UNW_FDE		" FDE: [0x%08llx]"
@ MSG_UNW_FDELNGTH	"    length: 0x%02x  cieptr: 0x%02x"
@ MSG_UNW_FDEINITLOC	"    initloc: 0x%08llx  addrrange: 0x%04llx"
@ MSG_UNW_FDEAUXVAL	"   Auxillary vals:"
@ MSG_UNW_FDEAUXSIZE	"      size: 0x%llx"
@ MSG_UNW_FDEAUXLSDA	"    lsda: 0x%llx"
@ MSG_UNW_FDECFI	"    CallFrameInstructions:"
@ MSG_UNW_FDECFI1	"\n      "
@ MSG_UNW_FDECFI2	"0x%02x "

# Note messages

@ MSG_NOTE_TYPE		"    type   %#x"
@ MSG_NOTE_NAMESZ	"    namesz %#x:"
@ MSG_NOTE_DESCSZ	"    descsz %#x:"
@ MSG_NOTE_DESC		"      desc[%d]\t%s"
@ MSG_NOTE_TOK		"%2.2x "
