/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Dump an elf file.
 */
#include	<machdep.h>
#include	<sys/elf_386.h>
#include	<sys/elf_amd64.h>
#include	<sys/elf_SPARC.h>
#include	<dwarf.h>
#include	<unistd.h>
#include	<errno.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<msg.h>
#include	<_elfdump.h>

/*
 * Focal point for verifying symbol names.
 */
static const char *
string(Cache *refsec, Word ndx, Cache *strsec, const char *file, Word name)
{
	static Cache	*osec = 0;
	static int	nostr;

	const char	*strs = (char *)strsec->c_data->d_buf;
	Word		strn = strsec->c_data->d_size;

	/*
	 * Only print a diagnostic regarding an empty string table once per
	 * input section being processed.
	 */
	if (osec != refsec) {
		osec = refsec;
		nostr = 0;
	}

	/*
	 * Is the string table offset within range of the available strings?
	 */
	if (name >= strn) {
		/*
		 * Do we have a empty string table?
		 */
		if (strs == 0) {
			if (nostr == 0) {
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
				    file, strsec->c_name);
				nostr++;
			}
		} else {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSTOFF),
			    file, refsec->c_name, EC_WORD(ndx), strsec->c_name,
			    EC_WORD(name), EC_WORD(strn - 1));
		}

		/*
		 * Return the empty string so that the calling function can
		 * continue it's output diagnostics.
		 */
		return (MSG_INTL(MSG_STR_UNKNOWN));
	}
	return (strs + name);
}

/*
 * Relocations can reference section symbols and standard symbols.  If the
 * former, establish the section name.
 */
static const char *
relsymname(Cache *cache, Cache *csec, Cache *strsec, Word symndx, Word symnum,
    Word relndx, Sym *syms, char *secstr, size_t secsz, const char *file,
    uint_t flags)
{
	Sym	*sym;

	if (symndx >= symnum) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_RELBADSYMNDX),
		    file, EC_WORD(symndx), EC_WORD(relndx));
		return (MSG_INTL(MSG_STR_UNKNOWN));
	}

	sym = (Sym *)(syms + symndx);

	/*
	 * If the symbol represents a section offset construct an appropriate
	 * string.
	 */
	if ((ELF_ST_TYPE(sym->st_info) == STT_SECTION) && (sym->st_name == 0)) {
		if (flags & FLG_LONGNAME)
			(void) snprintf(secstr, secsz,
			    MSG_INTL(MSG_STR_L_SECTION),
			    cache[sym->st_shndx].c_name);
		else
			(void) snprintf(secstr, secsz,
			    MSG_INTL(MSG_STR_SECTION),
			    cache[sym->st_shndx].c_name);
		return ((const char *)secstr);
	}

	return (string(csec, symndx, strsec, file, sym->st_name));
}

/*
 * Focal point for establishing a string table section.  Data such as the
 * dynamic information simply points to a string table.  Data such as
 * relocations, reference a symbol table, which in turn is associated with a
 * string table.
 */
static int
stringtbl(Cache *cache, int symtab, Word ndx, Word shnum, const char *file,
    Word *symnum, Cache **symsec, Cache **strsec)
{
	Shdr	*shdr = cache[ndx].c_shdr;

	if (symtab) {
		/*
		 * Validate the symbol table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, cache[ndx].c_name, EC_WORD(shdr->sh_link));
			return (0);
		}

		/*
		 * Obtain, and verify the symbol table data.
		 */
		if (cache[ndx].c_data->d_buf == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, cache[ndx].c_name);
			return (0);
		}

		/*
		 * Establish the string table index.
		 */
		ndx = shdr->sh_link;
		shdr = cache[ndx].c_shdr;

		/*
		 * Return symbol table information.
		 */
		if (symnum)
			*symnum = (shdr->sh_size / shdr->sh_entsize);
		if (symsec)
			*symsec = &cache[ndx];
	}

	/*
	 * Validate the associated string table section.
	 */
	if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
		    file, cache[ndx].c_name, EC_WORD(shdr->sh_link));
		return (0);
	}

	if (strsec)
		*strsec = &cache[shdr->sh_link];

	return (1);
}

/*
 * Lookup a symbol and set Sym accordingly.
 */
static int
symlookup(const char *name, Cache *cache, Word shnum, Sym **sym,
    Cache *symtab, const char *file)
{
	Shdr	*shdr;
	Word	symn, cnt;
	Sym	*syms;

	if (symtab == 0)
		return (0);

	shdr = symtab->c_shdr;

	/*
	 * Determine the symbol data and number.
	 */
	if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, symtab->c_name);
		return (0);
	}
	/* LINTED */
	symn = (Word)(shdr->sh_size / shdr->sh_entsize);
	syms = (Sym *)symtab->c_data->d_buf;

	/*
	 * Get the associated string table section.
	 */
	if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
		    file, symtab->c_name, EC_WORD(shdr->sh_link));
		return (0);
	}

	/*
	 * Loop through the symbol table to find a match.
	 */
	for (cnt = 0; cnt < symn; syms++, cnt++) {
		const char	*symname;

		symname = string(symtab, cnt, &cache[shdr->sh_link], file,
		    syms->st_name);

		if (symname && (strcmp(name, symname) == 0)) {
			*sym = syms;
			return (1);
		}
	}
	return (0);
}

/*
 * Print section headers.
 */
static void
sections(const char *file, Cache *cache, Word shnum, Ehdr *ehdr,
    const char *name)
{
	size_t	seccnt;

	for (seccnt = 1; seccnt < shnum; seccnt++) {
		Cache		*_cache = &cache[seccnt];
		Shdr		*shdr = _cache->c_shdr;
		const char	*secname = _cache->c_name;

		if (name && strcmp(name, secname))
			continue;

		/*
		 * Although numerous section header entries can be zero, it's
		 * usually a sign of trouble if the name or type are zero.
		 */
		if (shdr->sh_type == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHTYPE),
			    file, secname, EC_WORD(shdr->sh_type));
		}
		if (shdr->sh_name == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHNAME),
			    file, secname, EC_XWORD(shdr->sh_name));

			/*
			 * Use the empty string, rather than the fabricated
			 * name for the section output.
			 */
			secname = MSG_ORIG(MSG_STR_EMPTY);
		}

		/*
		 * Identify any sections that are suspicious.  A .got section
		 * shouldn't exist in a relocatable object.
		 */
		if (ehdr->e_type == ET_REL) {
			if (strncmp(secname, MSG_ORIG(MSG_ELF_GOT),
			    MSG_ELF_GOT_SIZE) == 0) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_GOT_UNEXPECTED), file,
				    secname);
			}
		}

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SHDR), EC_WORD(seccnt), secname);
		Elf_shdr(0, ehdr->e_machine, shdr);
	}
}

/*
 * A couple of instances of unwind data are printed as tables of 8 data items
 * expressed as 0x?? integers.
 */
#define	UNWINDTBLSZ	10 + (8 * 5) + 1

static void
unwindtbl(uint64_t *ndx, uint_t len, uchar_t *data, uint64_t doff,
    const char *msg, const char *pre, size_t plen)
{
	char	buffer[UNWINDTBLSZ];
	uint_t	boff = plen, cnt = 0;

	dbg_print(0, msg);
	(void) strncpy(buffer, pre, UNWINDTBLSZ);

	while (*ndx < (len + 4)) {
		if (cnt == 8) {
			dbg_print(0, buffer);
			boff = plen;
			cnt = 0;
		}
		(void) snprintf(&buffer[boff], UNWINDTBLSZ - boff,
		    MSG_ORIG(MSG_UNW_TBLENTRY), data[doff + (*ndx)++]);
		boff += 5;
		cnt++;
	}
	if (cnt)
		dbg_print(0, buffer);
}

/*
 * Obtain a specified Phdr entry.
 */
static Phdr *
getphdr(Word phnum, Word type, const char *file, Elf *elf)
{
	Word	cnt;
	Phdr	*phdr;

	if ((phdr = elf_getphdr(elf)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
		return (0);
	}

	for (cnt = 0; cnt < phnum; phdr++, cnt++) {
		if (phdr->p_type == type)
			return (phdr);
	}
	return (0);
}

static void
unwind(Cache *cache, Word shnum, Word phnum, Ehdr *ehdr, const char *name,
    const char *file, Elf *elf)
{
	Word	cnt;
	Phdr	*uphdr = 0;

	/*
	 * For the moment - UNWIND is only relevant for a AMD64 object.
	 */
	if (ehdr->e_machine != EM_AMD64)
		return;

	if (phnum)
		uphdr = getphdr(phnum, PT_SUNW_UNWIND, file, elf);

	for (cnt = 1; cnt < shnum; cnt++) {
		Cache		*_cache = &cache[cnt];
		Shdr		*shdr = _cache->c_shdr;
		uchar_t		*data;
		size_t		datasize;
		uint64_t	off, ndx, frame_ptr, fde_cnt, tabndx;
		uint_t		vers, frame_ptr_enc, fde_cnt_enc, table_enc;

		/*
		 * AMD64 - this is a strmcp() just to find the gcc produced
		 * sections.  Soon gcc should be setting the section type - and
		 * we'll not need this strcmp().
		 */
		if ((shdr->sh_type != SHT_AMD64_UNWIND) &&
		    (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRM),
		    MSG_SCN_FRM_SIZE) != 0) &&
		    (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRMHDR),
		    MSG_SCN_FRMHDR_SIZE) != 0))
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_UNWIND), _cache->c_name);

		data = (uchar_t *)(_cache->c_data->d_buf);
		datasize = _cache->c_data->d_size;
		off = 0;

		/*
		 * Is this a .eh_frame_hdr
		 */
		if ((uphdr && (shdr->sh_addr == uphdr->p_vaddr)) ||
		    (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRMHDR),
		    MSG_SCN_FRMHDR_SIZE) == 0)) {

			dbg_print(0, MSG_ORIG(MSG_UNW_FRMHDR));
			ndx = 0;

			vers = data[ndx++];
			frame_ptr_enc = data[ndx++];
			fde_cnt_enc = data[ndx++];
			table_enc = data[ndx++];

			dbg_print(0, MSG_ORIG(MSG_UNW_FRMVERS), vers);

			frame_ptr = dwarf_ehe_extract(data, &ndx, frame_ptr_enc,
			    ehdr->e_ident, shdr->sh_addr + ndx);

			dbg_print(0, MSG_ORIG(MSG_UNW_FRPTRENC),
			    conv_dwarf_ehe(frame_ptr_enc), EC_XWORD(frame_ptr));

			fde_cnt = dwarf_ehe_extract(data, &ndx, fde_cnt_enc,
			    ehdr->e_ident, shdr->sh_addr + ndx);

			dbg_print(0, MSG_ORIG(MSG_UNW_FDCNENC),
			    conv_dwarf_ehe(fde_cnt_enc), EC_XWORD(fde_cnt));
			dbg_print(0, MSG_ORIG(MSG_UNW_TABENC),
			    conv_dwarf_ehe(table_enc));
			dbg_print(0, MSG_ORIG(MSG_UNW_BINSRTAB1));
			dbg_print(0, MSG_ORIG(MSG_UNW_BINSRTAB2));

			for (tabndx = 0; tabndx < fde_cnt; tabndx++) {
				dbg_print(0, MSG_ORIG(MSG_UNW_BINSRTABENT),
				    EC_XWORD(dwarf_ehe_extract(data, &ndx,
				    table_enc, ehdr->e_ident, shdr->sh_addr)),
				    EC_XWORD(dwarf_ehe_extract(data, &ndx,
				    table_enc, ehdr->e_ident, shdr->sh_addr)));
			}
			continue;
		}

		/*
		 * Walk the Eh_frame's
		 */
		while (off < datasize) {
			uint_t		cieid, cielength, cieversion,
					cieretaddr;
			int		cieRflag, cieLflag, ciePflag, cieZflag;
			uint_t		cieaugndx, length, id;
			uint64_t	ciecalign, ciedalign;
			char		*cieaugstr;

			ndx = 0;
			/*
			 * extract length in lsb format
			 */
			length = LSB32EXTRACT(data + off + ndx);
			ndx += 4;

			/*
			 * extract CIE id in lsb format
			 */
			id = LSB32EXTRACT(data + off + ndx);
			ndx += 4;

			/*
			 * A CIE record has a id of '0', otherwise this is a
			 * FDE entry and the 'id' is the CIE pointer.
			 */
			if (id == 0) {
				uint64_t    persVal;

				cielength = length;
				cieid = id;
				cieLflag = ciePflag = cieRflag = cieZflag = 0;

				dbg_print(0, MSG_ORIG(MSG_UNW_CIE),
				    EC_XWORD(shdr->sh_addr + off));
				dbg_print(0, MSG_ORIG(MSG_UNW_CIELNGTH),
				    cielength, cieid);

				cieversion = data[off + ndx];
				ndx += 1;
				cieaugstr = (char *)(&data[off + ndx]);
				ndx += strlen(cieaugstr) + 1;

				dbg_print(0, MSG_ORIG(MSG_UNW_CIEVERS),
				    cieversion, cieaugstr);

				ciecalign = uleb_extract(&data[off], &ndx);
				ciedalign = sleb_extract(&data[off], &ndx);
				cieretaddr = data[off + ndx];
				ndx += 1;

				dbg_print(0, MSG_ORIG(MSG_UNW_CIECALGN),
				    EC_XWORD(ciecalign), EC_XWORD(ciedalign),
				    cieretaddr);

				if (cieaugstr[0])
				    dbg_print(0, MSG_ORIG(MSG_UNW_CIEAUXVAL));

				for (cieaugndx = 0; cieaugstr[cieaugndx];
				    cieaugndx++) {
					uint_t	val;

					switch (cieaugstr[cieaugndx]) {
					case 'z':
					    val = uleb_extract(&data[off],
						&ndx);
					    dbg_print(0,
						MSG_ORIG(MSG_UNW_CIEAUXSIZE),
						val);
					    cieZflag = 1;
					    break;
					case 'P':
					    ciePflag = data[off + ndx];
					    ndx += 1;

					    persVal = dwarf_ehe_extract(
						&data[off],
						&ndx, ciePflag, ehdr->e_ident,
						shdr->sh_addr + off + ndx);
					    dbg_print(0,
						MSG_ORIG(MSG_UNW_CIEAUXPERS),
						ciePflag,
						conv_dwarf_ehe(ciePflag),
						EC_XWORD(persVal));
					    break;
					case 'R':
					    val = data[off + ndx];
					    ndx += 1;
					    dbg_print(0,
						MSG_ORIG(MSG_UNW_CIEAUXCENC),
						val, conv_dwarf_ehe(val));
					    cieRflag = val;
					    break;
					case 'L':
					    val = data[off + ndx];
					    ndx += 1;
					    dbg_print(0,
						MSG_ORIG(MSG_UNW_CIEAUXLSDA),
						val, conv_dwarf_ehe(val));
					    cieLflag = val;
					    break;
					default:
					    dbg_print(0,
						MSG_ORIG(MSG_UNW_CIEAUXUNEC),
						cieaugstr[cieaugndx]);
					    break;
					}
				}
				if ((cielength + 4) > ndx)
					unwindtbl(&ndx, cielength, data, off,
					    MSG_ORIG(MSG_UNW_CIECFI),
					    MSG_ORIG(MSG_UNW_CIEPRE),
					    MSG_UNW_CIEPRE_SIZE);
				off += cielength + 4;

			} else {
				uint_t	    fdelength = length;
				int	    fdecieptr = id;
				uint64_t    fdeinitloc, fdeaddrrange;

				dbg_print(0, MSG_ORIG(MSG_UNW_FDE),
				    EC_XWORD(shdr->sh_addr + off));
				dbg_print(0, MSG_ORIG(MSG_UNW_FDELNGTH),
				    fdelength, fdecieptr);

				fdeinitloc = dwarf_ehe_extract(&data[off],
				    &ndx, cieRflag, ehdr->e_ident,
				    shdr->sh_addr + off + ndx);
				fdeaddrrange = dwarf_ehe_extract(&data[off],
				    &ndx, (cieRflag & ~DW_EH_PE_pcrel),
				    ehdr->e_ident,
				    shdr->sh_addr + off + ndx);

				dbg_print(0, MSG_ORIG(MSG_UNW_FDEINITLOC),
				    EC_XWORD(fdeinitloc),
				    EC_XWORD(fdeaddrrange));

				if (cieaugstr[0])
					dbg_print(0,
					    MSG_ORIG(MSG_UNW_FDEAUXVAL));
				if (cieZflag) {
					uint64_t    val;
					val = uleb_extract(&data[off], &ndx);
					dbg_print(0,
					    MSG_ORIG(MSG_UNW_FDEAUXSIZE),
					    EC_XWORD(val));
					if (val & cieLflag) {
					    fdeinitloc = dwarf_ehe_extract(
						&data[off], &ndx, cieLflag,
						ehdr->e_ident,
						shdr->sh_addr + off + ndx);
					    dbg_print(0,
						MSG_ORIG(MSG_UNW_FDEAUXLSDA),
						EC_XWORD(val));
					}
				}
				if ((fdelength + 4) > ndx)
					unwindtbl(&ndx, fdelength, data, off,
					    MSG_ORIG(MSG_UNW_FDECFI),
					    MSG_ORIG(MSG_UNW_FDEPRE),
					    MSG_UNW_FDEPRE_SIZE);
				off += fdelength + 4;
			}
		}
	}
}

/*
 * Print the hardware/software capabilities.  For executables and shared objects
 * this should be accompanied with a program header.
 */
static void
cap(const char *file, Cache *cache, Word shnum, Word phnum, Ehdr *ehdr,
    Elf *elf)
{
	Word		cnt;
	Shdr *		cshdr = 0;
	Cache *		ccache;
	Off		cphdr_off = 0;
	Xword		cphdr_sz;

	/*
	 * Determine if a hardware/software capabilities header exists.
	 */
	if (phnum) {
		Phdr	*phdr;

		if ((phdr = elf_getphdr(elf)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
			return;
		}

		for (cnt = 0; cnt < phnum; phdr++, cnt++) {
			if (phdr->p_type == PT_SUNWCAP) {
				cphdr_off = phdr->p_offset;
				cphdr_sz = phdr->p_filesz;
				break;
			}
		}
	}

	/*
	 * Determine if a hardware/software capabilities section exists.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;

		if (shdr->sh_type != SHT_SUNW_cap)
			continue;

		if (cphdr_off && ((cphdr_off < shdr->sh_offset) ||
		    (cphdr_off + cphdr_sz) > (shdr->sh_offset + shdr->sh_size)))
			continue;

		ccache = _cache;
		cshdr = shdr;
		break;
	}

	if ((cshdr == 0) && (cphdr_off == 0))
		return;

	/*
	 * Print the hardware/software capabilities section.
	 */
	if (cshdr) {
		Word	ndx, capn;
		Cap	*cap = (Cap *)ccache->c_data->d_buf;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_CAP), ccache->c_name);

		Elf_cap_title(0);

		capn = (Word)(cshdr->sh_size / cshdr->sh_entsize);

		for (ndx = 0; ndx < capn; cap++, ndx++) {
			if (cap->c_tag != CA_SUNW_NULL)
				Elf_cap_entry(0, cap, ndx, ehdr->e_machine);
		}
	} else
		(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVCAP1), file);

	/*
	 * If this object is an executable or shared object, then the
	 * hardware/software capabilities section should have an accompanying
	 * program header.
	 */
	if (cshdr && ((ehdr->e_type == ET_EXEC) || (ehdr->e_type == ET_DYN))) {
		if (cphdr_off == 0)
			(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVCAP2),
			    file, ccache->c_name);
		else if ((cphdr_off != cshdr->sh_offset) ||
		    (cphdr_sz != cshdr->sh_size))
			(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVCAP3),
			    file, ccache->c_name);
	}
}

/*
 * Print the interpretor.
 */
static void
interp(const char *file, Cache *cache, Word shnum, Word phnum, Elf *elf)
{
	Word	cnt;
	Shdr	*ishdr = 0;
	Cache	*icache;
	Off	iphdr_off = 0;
	Xword	iphdr_fsz;

	/*
	 * Determine if an interp header exists.
	 */
	if (phnum) {
		Phdr	*phdr;

		if ((phdr = getphdr(phnum, PT_INTERP, file, elf)) != 0) {
			iphdr_off = phdr->p_offset;
			iphdr_fsz = phdr->p_filesz;
		}
	}

	if (iphdr_off == 0)
		return;

	/*
	 * Determine if an interp section exists.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;

		/*
		 * Scan sections to find a section which contains the PT_INTERP
		 * string.  The target section can't be in a NOBITS section.
		 */
		if ((shdr->sh_type == SHT_NOBITS) ||
		    (iphdr_off < shdr->sh_offset) ||
		    (iphdr_off + iphdr_fsz) > (shdr->sh_offset + shdr->sh_size))
			continue;

		icache = _cache;
		ishdr = shdr;
		break;
	}

	/*
	 * Print the interpreter string based on the offset defined in the
	 * program header, as this is the offset used by the kernel.
	 */
	if (ishdr) {
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_INTERP), icache->c_name);
		dbg_print(0, MSG_ORIG(MSG_FMT_INDENT),
		    (char *)icache->c_data->d_buf +
		    (iphdr_off - ishdr->sh_offset));
	} else
		(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVINTERP1), file);

	/*
	 * If there are any inconsistences between the program header and
	 * section information, flag them.
	 */
	if (ishdr && ((iphdr_off != ishdr->sh_offset) ||
	    (iphdr_fsz != ishdr->sh_size))) {
		(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVINTERP2), file,
		    icache->c_name);
	}
}

/*
 * Print the syminfo section.
 */
static void
syminfo(Cache *cache, Word shnum, const char *file)
{
	Shdr		*infoshdr;
	Syminfo		*info;
	Sym		*syms;
	Dyn		*dyns;
	Word		infonum, cnt, ndx, symnum;
	Cache		*infocache = 0, *symsec, *strsec;

	for (cnt = 1; cnt < shnum; cnt++) {
		if (cache[cnt].c_shdr->sh_type == SHT_SUNW_syminfo) {
			infocache = &cache[cnt];
			break;
		}
	}
	if (infocache == 0)
		return;

	infoshdr = infocache->c_shdr;
	if ((infoshdr->sh_entsize == 0) || (infoshdr->sh_size == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, infocache->c_name);
		return;
	}
	infonum = (Word)(infoshdr->sh_size / infoshdr->sh_entsize);
	info = (Syminfo *)infocache->c_data->d_buf;

	/*
	 * Get the data buffer of the associated dynamic section.
	 */
	if ((infoshdr->sh_info == 0) || (infoshdr->sh_info >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHINFO),
		    file, infocache->c_name, EC_WORD(infoshdr->sh_info));
		return;
	}
	dyns = cache[infoshdr->sh_info].c_data->d_buf;
	if (dyns == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, cache[infoshdr->sh_info].c_name);
		return;
	}

	/*
	 * Get the data buffer for the associated symbol table and string table.
	 */
	if (stringtbl(cache, 1, cnt, shnum, file,
	    &symnum, &symsec, &strsec) == 0)
		return;

	syms = symsec->c_data->d_buf;

	/*
	 * Loop through the syminfo entries.
	 */
	dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(0, MSG_INTL(MSG_ELF_SCN_SYMINFO), infocache->c_name);
	Elf_syminfo_title(0);

	for (ndx = 1, info++; ndx < infonum; ndx++, info++) {
		Sym 		*sym;
		const char	*needed = 0, *name;

		if ((info->si_flags == 0) && (info->si_boundto == 0))
			continue;

		sym = &syms[ndx];
		name = string(infocache, ndx, strsec, file, sym->st_name);

		if (info->si_boundto < SYMINFO_BT_LOWRESERVE) {
			Dyn	*dyn = &dyns[info->si_boundto];

			needed = string(infocache, info->si_boundto,
			    strsec, file, dyn->d_un.d_val);
		}
		Elf_syminfo_entry(0, ndx, info, name, needed);
	}
}

/*
 * Print version definition section entries.
 */
static void
version_def(Verdef *vdf, Word shnum, Cache *vcache, Cache *scache,
    const char *file)
{
	Word	cnt;
	char	index[MAXNDXSIZE];

	Elf_ver_def_title(0);

	for (cnt = 1; cnt <= shnum; cnt++,
	    vdf = (Verdef *)((uintptr_t)vdf + vdf->vd_next)) {
		const char	*name, *dep;
		Half		vcnt = vdf->vd_cnt - 1;
		Half		ndx = vdf->vd_ndx;
		Verdaux		*vdap = (Verdaux *)((uintptr_t)vdf +
				    vdf->vd_aux);

		/*
		 * Obtain the name and first dependency (if any).
		 */
		name = string(vcache, cnt, scache, file, vdap->vda_name);
		vdap = (Verdaux *)((uintptr_t)vdap + vdap->vda_next);
		if (vcnt)
			dep = string(vcache, cnt, scache, file, vdap->vda_name);
		else
			dep = MSG_ORIG(MSG_STR_EMPTY);

		(void) snprintf(index, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INDEX),
		    EC_XWORD(ndx));
		Elf_ver_line_1(0, index, name, dep,
		    conv_ver_flags(vdf->vd_flags));

		/*
		 * Print any additional dependencies.
		 */
		if (vcnt) {
			vdap = (Verdaux *)((uintptr_t)vdap + vdap->vda_next);
			for (vcnt--; vcnt; vcnt--,
			    vdap = (Verdaux *)((uintptr_t)vdap +
			    vdap->vda_next)) {
				dep = string(vcache, cnt, scache, file,
				    vdap->vda_name);
				Elf_ver_line_2(0, MSG_ORIG(MSG_STR_EMPTY), dep);
			}
		}
	}
}

/*
 * Print a version needed section entries.
 */
static void
version_need(Verneed *vnd, Word shnum, Cache *vcache, Cache *scache,
    const char *file)
{
	Word	cnt;

	Elf_ver_need_title(0);

	for (cnt = 1; cnt <= shnum; cnt++,
	    vnd = (Verneed *)((uintptr_t)vnd + vnd->vn_next)) {
		const char	*name, *dep;
		Half		vcnt = vnd->vn_cnt;
		Vernaux		*vnap = (Vernaux *)((uintptr_t)vnd +
					vnd->vn_aux);

		/*
		 * Obtain the name of the needed file and the version name
		 * within it that we're dependent on.  Note that the count
		 * should be at least one, otherwise this is a pretty bogus
		 * entry.
		 */
		name = string(vcache, cnt, scache, file, vnd->vn_file);
		if (vcnt)
			dep = string(vcache, cnt, scache, file, vnap->vna_name);
		else
			dep = MSG_INTL(MSG_STR_NULL);

		Elf_ver_line_1(0, MSG_ORIG(MSG_STR_EMPTY), name, dep,
		    conv_ver_flags(vnap->vna_flags));

		/*
		 * Print any additional version dependencies.
		 */
		if (vcnt) {
			vnap = (Vernaux *)((uintptr_t)vnap + vnap->vna_next);
			for (vcnt--; vcnt; vcnt--,
			    vnap = (Vernaux *)((uintptr_t)vnap +
			    vnap->vna_next)) {
				dep = string(vcache, cnt, scache, file,
				    vnap->vna_name);
				Elf_ver_line_3(0, MSG_ORIG(MSG_STR_EMPTY), dep,
				    conv_ver_flags(vnap->vna_flags));
			}
		}
	}
}

/*
 * Search for any version sections - the Versym output is possibly used by the
 * symbols() printing.  If VERSYM is specified - then display the version
 * information.
 */
static Cache *
versions(Cache *cache, Word shnum, const char *file, uint_t flags)
{
	GElf_Word	cnt;
	Cache		*versymcache = 0;

	for (cnt = 1; cnt < shnum; cnt++) {
		void		*ver;
		uint_t		num;
		Cache		*_cache = &cache[cnt];
		Shdr		*shdr = _cache->c_shdr;
		const char	*secname = _cache->c_name;

		/*
		 * If this is the version symbol table simply record its
		 * data address for possible use in later symbol processing.
		 */
		if (shdr->sh_type == SHT_SUNW_versym) {
			versymcache = _cache;
			continue;
		}

		if ((flags & FLG_VERSIONS) == 0)
			continue;

		if ((shdr->sh_type != SHT_SUNW_verdef) &&
		    (shdr->sh_type != SHT_SUNW_verneed))
			continue;

		/*
		 * Determine the version section data and number.
		 */
		if ((ver = (void *)_cache->c_data->d_buf) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, secname);
			continue;
		}
		if ((num = shdr->sh_info) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHINFO),
			    file, secname, EC_WORD(shdr->sh_info));
			continue;
		}

		/*
		 * Get the data buffer for the associated string table.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, secname, EC_WORD(shdr->sh_link));
			continue;
		}

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		if (shdr->sh_type == SHT_SUNW_verdef) {
			dbg_print(0, MSG_INTL(MSG_ELF_SCN_VERDEF), secname);
			version_def((Verdef *)ver, num, _cache,
			    &cache[shdr->sh_link], file);
		} else if (shdr->sh_type == SHT_SUNW_verneed) {
			dbg_print(0, MSG_INTL(MSG_ELF_SCN_VERNEED), secname);
			version_need((Verneed *)ver, num, _cache,
			    &cache[shdr->sh_link], file);
		}
	}
	return (versymcache);
}

/*
 * Determine the extended section index used for symbol tables entries.
 */
static int
symbols_getxindex(Cache *cache, Word shnum, Word seccnt, Word **shxndx,
    uint_t *symnshxndx)
{
	uint_t	symn;
	Word	symcnt;

	for (symcnt = 1; symcnt < shnum; symcnt++) {
		Cache	*_cache = &cache[symcnt];
		Shdr	*shdr = _cache->c_shdr;

		if ((shdr->sh_type != SHT_SYMTAB_SHNDX) ||
		    (shdr->sh_link != seccnt))
			continue;

		if ((shdr->sh_entsize) &&
		    /* LINTED */
		    ((symn = (uint_t)(shdr->sh_size / shdr->sh_entsize)) == 0))
			continue;

		*shxndx = _cache->c_data->d_buf;
		*symnshxndx = symn;
		return (0);
	}
	return (1);
}

/*
 * Search for and process any symbol tables.
 */
void
symbols(Cache *cache, Word shnum, Ehdr *ehdr, const char *name,
    Cache *versymcache, const char *file, uint_t flags)
{
	Word	seccnt;
	char	is_core = (ehdr->e_type == ET_CORE);

	for (seccnt = 1; seccnt < shnum; seccnt++) {
		Word		symn, symcnt, *shxndx;
		Versym		*versym;
		Cache		*_cache = &cache[seccnt];
		Shdr		*shdr = _cache->c_shdr;
		const char	*secname = _cache->c_name;
		Sym 		*sym;
		int		noshxndx;
		uint_t		symnshxndx;

		if ((shdr->sh_type != SHT_SYMTAB) &&
		    (shdr->sh_type != SHT_DYNSYM))
			continue;
		if (name && strcmp(name, secname))
			continue;

		/*
		 * Determine the symbol data and number.
		 */
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, secname);
			continue;
		}
		/* LINTED */
		symn = (Word)(shdr->sh_size / shdr->sh_entsize);
		sym = (Sym *)_cache->c_data->d_buf;

		/*
		 * Get the associated string table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, secname, EC_WORD(shdr->sh_link));
			continue;
		}

		/*
		 * Determine if there is a associated Versym section
		 * with this Symbol Table.
		 */
		if (versymcache && (versymcache->c_shdr->sh_link == seccnt))
			versym = versymcache->c_data->d_buf;
		else
			versym = 0;

		/*
		 * Loop through the symbol tables entries.
		 */
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_SYMTAB), secname);
		Elf_syms_table_title(0, ELF_DBG_ELFDUMP);

		shxndx = 0;
		noshxndx = 0;
		symnshxndx = 0;
		for (symcnt = 0; symcnt < symn; sym++, symcnt++) {
			char		index[MAXNDXSIZE], *sec;
			const char	*symname;
			int		verndx;
			uchar_t		type;
			Shdr		*tshdr;
			Word		shndx;

			/*
			 * If we are using extended symbol indexes, find the
			 * corresponding SHN_SYMTAB_SHNDX table.
			 */
			if ((sym->st_shndx == SHN_XINDEX) &&
			    (shxndx == 0) && (noshxndx == 0))
				noshxndx = symbols_getxindex(cache, shnum,
				    seccnt, &shxndx, &symnshxndx);

			/* LINTED */
			symname = string(_cache, symcnt, &cache[shdr->sh_link],
			    file, sym->st_name);

			tshdr = 0;
			sec = NULL;

			if (is_core)
				sec = (char *)MSG_INTL(MSG_STR_UNKNOWN);
			else if ((sym->st_shndx < SHN_LORESERVE) &&
			    (sym->st_shndx < shnum)) {
				shndx = sym->st_shndx;
				tshdr = cache[shndx].c_shdr;
				sec = cache[shndx].c_name;
			} else if (sym->st_shndx == SHN_XINDEX) {
				if (shxndx) {
					Word	_shxndx;

					if (symcnt > symnshxndx) {
					    (void) fprintf(stderr,
						MSG_INTL(MSG_ERR_BADSYMXINDEX1),
						file, secname, EC_WORD(symcnt));
					} else if ((_shxndx =
					    shxndx[symcnt]) > shnum) {
					    (void) fprintf(stderr,
						MSG_INTL(MSG_ERR_BADSYMXINDEX2),
						file, secname, EC_WORD(symcnt),
						EC_WORD(_shxndx));
					} else {
					    shndx = _shxndx;
					    tshdr = cache[shndx].c_shdr;
					    sec = cache[shndx].c_name;
					}
				} else {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_BADSYMXINDEX3),
					    file, secname, EC_WORD(symcnt));
				}
			} else if ((sym->st_shndx < SHN_LORESERVE) &&
			    (sym->st_shndx >= shnum)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYM5), file,
				    secname, demangle(symname, flags),
				    sym->st_shndx);
			}

			/*
			 * If versioning is available display the
			 * version index.
			 */
			if (versym)
				verndx = (int)versym[symcnt];
			else
				verndx = 0;

			/*
			 * Error checking for TLS.
			 */
			type = ELF_ST_TYPE(sym->st_info);
			if (type == STT_TLS) {
				if (tshdr &&
				    (sym->st_shndx != SHN_UNDEF) &&
				    ((tshdr->sh_flags & SHF_TLS) == 0)) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_BADSYM3), file,
					    secname, demangle(symname, flags));
				}
			} else if ((type != STT_SECTION) && sym->st_size &&
			    tshdr && (tshdr->sh_flags & SHF_TLS)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYM4), file,
				    secname, demangle(symname, flags));
			}

			/*
			 * If a symbol has size, then make sure the section it
			 * references is appropriate.  Note, UNDEF symbols that
			 * have a size, have been known to exist - ignore them.
			 */
			if (sym->st_size && shndx && tshdr &&
			    (tshdr->sh_size < sym->st_size)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYM6), file,
				    secname, demangle(symname, flags),
				    EC_WORD(shndx), EC_XWORD(tshdr->sh_size),
				    EC_XWORD(sym->st_size));
			}

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(symcnt));
			Elf_syms_table_entry(0, ELF_DBG_ELFDUMP, index,
			    ehdr->e_machine, sym, verndx, sec, symname);
		}
	}
}

/*
 * Search for and process any relocation sections.
 */
static void
reloc(Cache *cache, Word shnum, Ehdr *ehdr, const char *name, const char *file,
    uint_t flags)
{
	Word	cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		Word		type, symnum;
		Xword		relndx, relnum, relsize;
		void		*rels;
		Sym		*syms;
		Cache		*symsec, *strsec;
		Cache		*_cache = &cache[cnt];
		Shdr		*shdr = _cache->c_shdr;
		char		*relname = _cache->c_name;

		if (((type = shdr->sh_type) != SHT_RELA) &&
		    (type != SHT_REL))
			continue;
		if (name && strcmp(name, relname))
			continue;

		/*
		 * Decide entry size.
		 */
		if (((relsize = shdr->sh_entsize) == 0) ||
		    (relsize > shdr->sh_size)) {
			if (type == SHT_RELA)
				relsize = sizeof (Rela);
			else
				relsize = sizeof (Rel);
		}

		/*
		 * Determine the number of relocations available.
		 */
		if (shdr->sh_size == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, relname);
			continue;
		}
		rels = _cache->c_data->d_buf;
		relnum = shdr->sh_size / relsize;

		/*
		 * Get the data buffer for the associated symbol table and
		 * string table.
		 */
		if (stringtbl(cache, 1, cnt, shnum, file,
		    &symnum, &symsec, &strsec) == 0)
			continue;

		syms = symsec->c_data->d_buf;

		/*
		 * Loop through the relocation entries.
		 */
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_RELOC), _cache->c_name);
		Elf_reloc_title(0, ELF_DBG_ELFDUMP, type);

		for (relndx = 0; relndx < relnum; relndx++,
		    rels = (void *)((char *)rels + relsize)) {
			char		section[BUFSIZ];
			const char	*symname;
			Word		symndx, reltype;
			Rela		*rela;
			Rel		*rel;

			/*
			 * Unravel the relocation and determine the symbol with
			 * which this relocation is associated.
			 */
			if (type == SHT_RELA) {
				rela = (Rela *)rels;
				symndx = ELF_R_SYM(rela->r_info);
				reltype = ELF_R_TYPE(rela->r_info);
			} else {
				rel = (Rel *)rels;
				symndx = ELF_R_SYM(rel->r_info);
				reltype = ELF_R_TYPE(rel->r_info);
			}

			symname = relsymname(cache, _cache, strsec, symndx,
			    symnum, relndx, syms, section, BUFSIZ, file,
			    flags);

			/*
			 * A zero symbol index is only valid for a few
			 * relocations.
			 */
			if (symndx == 0) {
				Half	mach = ehdr->e_machine;
				int	badrel = 0;

				if ((mach == EM_SPARC) ||
				    (mach == EM_SPARC32PLUS) ||
				    (mach == EM_SPARCV9)) {
					if ((reltype != R_SPARC_NONE) &&
					    (reltype != R_SPARC_REGISTER) &&
					    (reltype != R_SPARC_RELATIVE))
						badrel++;
				} else if (mach == EM_386) {
					if ((reltype != R_386_NONE) &&
					    (reltype != R_386_RELATIVE))
						badrel++;
				} else if (mach == EM_AMD64) {
					if ((reltype != R_AMD64_NONE) &&
					    (reltype != R_AMD64_RELATIVE))
						badrel++;
				}

				if (badrel) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_BADREL1), file,
					    conv_reloc_type(mach, reltype, 0));
				}
			}

			Elf_reloc_entry_1(0, ELF_DBG_ELFDUMP,
			    MSG_ORIG(MSG_STR_EMPTY), ehdr->e_machine, type,
			    rels, relname, symname, 0);
		}
	}
}

/*
 * Search for and process a .dynamic section.
 */
static void
dynamic(Cache *cache, Word shnum, Ehdr *ehdr, const char *file)
{
	Word	cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		Dyn	*dyn;
		ulong_t	numdyn;
		int	ndx;
		Cache	*_cache = &cache[cnt], *strsec;
		Shdr	*shdr = _cache->c_shdr;

		if (shdr->sh_type != SHT_DYNAMIC)
			continue;

		/*
		 * Verify the associated string table section.
		 */
		if (stringtbl(cache, 0, cnt, shnum, file, 0, 0, &strsec) == 0)
			continue;

		numdyn = shdr->sh_size / shdr->sh_entsize;
		dyn = (Dyn *)_cache->c_data->d_buf;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_DYNAMIC), _cache->c_name);

		Elf_dyn_title(0);

		for (ndx = 0; ndx < numdyn; dyn++, ndx++) {
			const char	*name;

			/*
			 * Print the information numerically, and if possible
			 * as a string.
			 */
			if ((dyn->d_tag == DT_NEEDED) ||
			    (dyn->d_tag == DT_SONAME) ||
			    (dyn->d_tag == DT_FILTER) ||
			    (dyn->d_tag == DT_AUXILIARY) ||
			    (dyn->d_tag == DT_CONFIG) ||
			    (dyn->d_tag == DT_RPATH) ||
			    (dyn->d_tag == DT_RUNPATH) ||
			    (dyn->d_tag == DT_USED) ||
			    (dyn->d_tag == DT_DEPAUDIT) ||
			    (dyn->d_tag == DT_AUDIT) ||
			    (dyn->d_tag == DT_SUNW_AUXILIARY) ||
			    (dyn->d_tag == DT_SUNW_FILTER))
				name = string(_cache, ndx, strsec,
				    file, dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_FLAGS)
				name = conv_dyn_flag(dyn->d_un.d_val, 0);
			else if (dyn->d_tag == DT_FLAGS_1)
				name = conv_dyn_flag1(dyn->d_un.d_val);
			else if (dyn->d_tag == DT_POSFLAG_1)
				name = conv_dyn_posflag1(dyn->d_un.d_val, 0);
			else if (dyn->d_tag == DT_FEATURE_1)
				name = conv_dyn_feature1(dyn->d_un.d_val, 0);
			else if (dyn->d_tag == DT_DEPRECATED_SPARC_REGISTER)
				name = MSG_INTL(MSG_STR_DEPRECATED);
			else
				name = MSG_ORIG(MSG_STR_EMPTY);

			Elf_dyn_entry(0, dyn, ndx, name, ehdr->e_machine);
		}
	}
}

/*
 * Search for and process a MOVE section.
 */
static void
move(Cache *cache, Word shnum, const char *name, const char *file, uint_t flags)
{
	Word		cnt;
	const char	*fmt = 0;

	for (cnt = 1; cnt < shnum; cnt++) {
		Word	movenum, symnum, ndx;
		Sym	*syms;
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;
		Cache	*symsec, *strsec;
		Move	*move;

		if (shdr->sh_type != SHT_SUNW_move)
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;

		/*
		 * Determine the move data and number.
		 */
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			continue;
		}
		move = (Move *)_cache->c_data->d_buf;
		movenum = shdr->sh_size / shdr->sh_entsize;

		/*
		 * Get the data buffer for the associated symbol table and
		 * string table.
		 */
		if (stringtbl(cache, 1, cnt, shnum, file,
		    &symnum, &symsec, &strsec) == 0)
			return;

		syms = (Sym *)symsec->c_data->d_buf;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_MOVE), _cache->c_name);
		dbg_print(0, MSG_INTL(MSG_MOVE_TITLE));

		if (fmt == 0)
			fmt = MSG_INTL(MSG_MOVE_ENTRY);

		for (ndx = 0; ndx < movenum; move++, ndx++) {
			const char	*symname;
			char		index[MAXNDXSIZE], section[BUFSIZ];
			Word		symndx, shndx;
			Sym		*sym;

			/*
			 * Check for null entries
			 */
			if ((move->m_info == 0) && (move->m_value == 0) &&
			    (move->m_poffset == 0) && (move->m_repeat == 0) &&
			    (move->m_stride == 0)) {
				dbg_print(0, fmt, MSG_ORIG(MSG_STR_EMPTY),
				    EC_XWORD(move->m_poffset), 0, 0, 0,
				    EC_LWORD(0), MSG_ORIG(MSG_STR_EMPTY));
				continue;
			}
			if (((symndx = ELF_M_SYM(move->m_info)) == 0) ||
			    (symndx >= symnum)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADMINFO), file,
				    _cache->c_name, EC_XWORD(move->m_info));

				(void) snprintf(index, MAXNDXSIZE,
				    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(symndx));
				dbg_print(0, fmt, index,
				    EC_XWORD(move->m_poffset),
				    ELF_M_SIZE(move->m_info), move->m_repeat,
				    move->m_stride, move->m_value,
				    MSG_INTL(MSG_STR_UNKNOWN));
				continue;
			}

			symname = relsymname(cache, _cache, strsec,
			    symndx, symnum, ndx, syms, section, BUFSIZ, file,
			    flags);
			sym = (Sym *)(syms + symndx);

			/*
			 * Additional sanity check.
			 */
			shndx = sym->st_shndx;
			if (!((shndx == SHN_COMMON) ||
			    (((shndx >= 1) && (shndx <= shnum)) &&
			    (cache[shndx].c_shdr)->sh_type == SHT_NOBITS))) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYM2), file,
				    _cache->c_name, demangle(symname, flags));
			}

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(symndx));
			dbg_print(0, fmt, index, EC_XWORD(move->m_poffset),
			    ELF_M_SIZE(move->m_info), move->m_repeat,
			    move->m_stride, move->m_value,
			    demangle(symname, flags));
		}
	}
}

/*
 * Traverse a note section analyzing each note information block.
 * The data buffers size is used to validate references before they are made,
 * and is decremented as each element is processed.
 */
void
note_entry(Cache *cache, Word *data, size_t size, const char *file)
{
	size_t	bsize = size;

	/*
	 * Print out a single `note' information block.
	 */
	while (size > 0) {
		size_t	namesz, descsz, type, pad, noteoff;

		noteoff = bsize - size;
		/*
		 * Make sure we can at least reference the 3 initial entries
		 * (4-byte words) of the note information block.
		 */
		if (size >= (sizeof (Word) * 3))
			size -= (sizeof (Word) * 3);
		else {
			(void) fprintf(stderr, MSG_INTL(MSG_NOTE_BADDATASZ),
			    file, cache->c_name, EC_WORD(noteoff));
			return;
		}

		/*
		 * Make sure any specified name string can be referenced.
		 */
		if ((namesz = *data++) != 0) {
			if (size >= namesz)
				size -= namesz;
			else {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_NOTE_BADNMSZ), file,
				    cache->c_name, EC_WORD(noteoff),
				    EC_WORD(namesz));
				return;
			}
		}

		/*
		 * Make sure any specified descriptor can be referenced.
		 */
		if ((descsz = *data++) != 0) {
			/*
			 * If namesz isn't a 4-byte multiple, account for any
			 * padding that must exist before the descriptor.
			 */
			if ((pad = (namesz & (sizeof (Word) - 1))) != 0) {
				pad = sizeof (Word) - pad;
				size -= pad;
			}
			if (size >= descsz)
				size -= descsz;
			else {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_NOTE_BADDESZ), file,
				    cache->c_name, EC_WORD(noteoff),
				    EC_WORD(namesz));
				return;
			}
		}

		type = *data++;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_ORIG(MSG_NOTE_TYPE), EC_WORD(type));

		dbg_print(0, MSG_ORIG(MSG_NOTE_NAMESZ), EC_WORD(namesz));
		if (namesz) {
			char	*name = (char *)data;

			/*
			 * Since the name string may have 'null' bytes
			 * in it (ia32 .string) - we just write the
			 * whole stream in a single fwrite.
			 */
			(void) fwrite(name, namesz, 1, stdout);
			name = name + ((namesz + (sizeof (Word) - 1)) &
			    ~(sizeof (Word) - 1));
			/* LINTED */
			data = (Word *)name;
			dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		}

		/*
		 * If multiple information blocks exist within a .note section
		 * account for any padding that must exist before the next
		 * information block.
		 */
		if ((pad = (descsz & (sizeof (Word) - 1))) != 0) {
			pad = sizeof (Word) - pad;
			if (size > pad)
				size -= pad;
		}

		dbg_print(0, MSG_ORIG(MSG_NOTE_DESCSZ), EC_WORD(descsz));
		if (descsz) {
			int		ndx, byte, word;
			char		string[58], *str = string;
			uchar_t		*desc = (uchar_t *)data;

			/*
			 * Dump descriptor bytes.
			 */
			for (ndx = byte = word = 0; descsz; descsz--, desc++) {
				int	tok = *desc;

				(void) snprintf(str, 58, MSG_ORIG(MSG_NOTE_TOK),
				    tok);
				str += 3;

				if (++byte == 4) {
					*str++ = ' ', *str++ = ' ';
					word++;
					byte = 0;
				}
				if (word == 4) {
					*str = '\0';
					dbg_print(0, MSG_ORIG(MSG_NOTE_DESC),
					    ndx, string);
					word = 0;
					ndx += 16;
					str = string;
				}
			}
			if (byte || word) {
				*str = '\0';
				dbg_print(0, MSG_ORIG(MSG_NOTE_DESC),
				    ndx, string);
			}

			desc += pad;
			/* LINTED */
			data = (Word *)desc;
		}
	}
}

/*
 * Search for and process a .note section.
 */
static void
note(Cache *cache, Word shnum, const char *name, const char *file)
{
	Word	cnt;

	/*
	 * Otherwise look for any .note sections.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;

		if (shdr->sh_type != SHT_NOTE)
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;

		/*
		 * As these sections are often hand rolled, make sure they're
		 * properly aligned before proceeding.
		 */
		if (shdr->sh_offset & (sizeof (Word) - 1)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADALIGN),
			    file, _cache->c_name);
			continue;
		}

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_NOTE), _cache->c_name);
		note_entry(_cache, (Word *)_cache->c_data->d_buf,
		/* LINTED */
		    (Word)_cache->c_data->d_size, file);
	}
}

/*
 * Determine an individual hash entry.  This may be the initial hash entry,
 * or an associated chain entry.
 */
static void
hash_entry(Cache *refsec, Cache *strsec, const char *hsecname, Word hashndx,
    Word symndx, Word symn, Sym *syms, const char *file, ulong_t bkts,
    uint_t flags, int chain)
{
	Sym		*sym;
	const char	*symname, *str;
	char		_bucket[MAXNDXSIZE], _symndx[MAXNDXSIZE];
	ulong_t		nbkt, nhash;

	if (symndx > symn) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_HSBADSYMNDX), file,
		    EC_WORD(symndx), EC_WORD(hashndx));
		symname = MSG_INTL(MSG_STR_UNKNOWN);
	} else {
		sym = (Sym *)(syms + symndx);
		symname = string(refsec, symndx, strsec, file, sym->st_name);
	}

	if (chain == 0) {
		(void) snprintf(_bucket, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INTEGER),
		    hashndx);
		str = (const char *)_bucket;
	} else
		str = MSG_ORIG(MSG_STR_EMPTY);

	(void) snprintf(_symndx, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INDEX2),
	    EC_WORD(symndx));
	dbg_print(0, MSG_ORIG(MSG_FMT_HASH_INFO), str, _symndx,
	    demangle(symname, flags));

	/*
	 * Determine if this string is in the correct bucket.
	 */
	nhash = elf_hash(symname);
	nbkt = nhash % bkts;

	if (nbkt != hashndx) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADHASH), file,
		    hsecname, symname, EC_WORD(hashndx), nbkt);
	}
}

#define	MAXCOUNT	500

static void
hash(Cache *cache, Word shnum, const char *name, const char *file, uint_t flags)
{
	static int	count[MAXCOUNT];
	Word		cnt;
	ulong_t		ndx, bkts;
	char		number[MAXNDXSIZE];

	for (cnt = 1; cnt < shnum; cnt++) {
		uint_t		*hash, *chain;
		Cache		*_cache = &cache[cnt];
		Shdr		*sshdr, *hshdr = _cache->c_shdr;
		char		*ssecname, *hsecname = _cache->c_name;
		Sym		*syms;
		Word		symn;

		if (hshdr->sh_type != SHT_HASH)
			continue;
		if (name && strcmp(name, hsecname))
			continue;

		/*
		 * Determine the hash table data and size.
		 */
		if ((hshdr->sh_entsize == 0) || (hshdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, hsecname);
			continue;
		}
		hash = (uint_t *)_cache->c_data->d_buf;
		bkts = *hash;
		chain = hash + 2 + bkts;
		hash += 2;

		/*
		 * Get the data buffer for the associated symbol table.
		 */
		if ((hshdr->sh_link == 0) || (hshdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, hsecname, EC_WORD(hshdr->sh_link));
			continue;
		}

		_cache = &cache[hshdr->sh_link];
		ssecname = _cache->c_name;

		if ((syms = (Sym *)_cache->c_data->d_buf) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, ssecname);
			continue;
		}

		sshdr = _cache->c_shdr;
		/* LINTED */
		symn = (Word)(sshdr->sh_size / sshdr->sh_entsize);

		/*
		 * Get the associated string table section.
		 */
		if ((sshdr->sh_link == 0) || (sshdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, ssecname, EC_WORD(sshdr->sh_link));
			continue;
		}

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_HASH), hsecname);
		dbg_print(0, MSG_INTL(MSG_ELF_HASH_INFO));

		/*
		 * Loop through the hash buckets, printing the appropriate
		 * symbols.
		 */
		for (ndx = 0; ndx < bkts; ndx++, hash++) {
			Word	_ndx, _cnt;

			if (*hash == 0) {
				count[0]++;
				continue;
			}

			hash_entry(_cache, &cache[sshdr->sh_link], hsecname,
			    ndx, *hash, symn, syms, file, bkts, flags, 0);

			/*
			 * Determine if any other symbols are chained to this
			 * bucket.
			 */
			_ndx = chain[*hash];
			_cnt = 1;
			while (_ndx) {
				hash_entry(_cache, &cache[sshdr->sh_link],
				    hsecname, ndx, _ndx, symn, syms, file,
				    bkts, flags, 1);
				_ndx = chain[_ndx];
				_cnt++;
			}

			if (_cnt >= MAXCOUNT) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_HASH_OVERFLW), file,
				    _cache->c_name, EC_WORD(ndx),
				    EC_WORD(_cnt));
			} else
				count[_cnt]++;
		}
		break;
	}

	/*
	 * Print out the count information.
	 */
	bkts = cnt = 0;
	dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));

	for (ndx = 0; ndx < MAXCOUNT; ndx++) {
		Word	_cnt;

		if ((_cnt = count[ndx]) == 0)
			continue;

		(void) snprintf(number, MAXNDXSIZE,
		    MSG_ORIG(MSG_FMT_INTEGER), _cnt);
		dbg_print(0, MSG_INTL(MSG_ELF_HASH_BKTS1), number,
		    EC_WORD(ndx));
		bkts += _cnt;
		cnt += (Word)(ndx * _cnt);
	}
	if (cnt) {
		(void) snprintf(number, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INTEGER),
		    bkts);
		dbg_print(0, MSG_INTL(MSG_ELF_HASH_BKTS2), number,
		    EC_WORD(cnt));
	}
}

static void
group(Cache *cache, Word shnum, const char *name, const char *file,
    uint_t flags)
{
	Word	scnt;

	for (scnt = 1; scnt < shnum; scnt++) {
		Cache	*_cache = &cache[scnt];
		Shdr	*shdr = _cache->c_shdr;
		Word	*grpdata, gcnt, grpcnt, symnum, unknown;
		Cache	*symsec, *strsec;
		Sym	*syms, *sym;
		char	flgstrbuf[MSG_GRP_COMDAT_SIZE + 10];

		if (shdr->sh_type != SHT_GROUP)
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;
		if ((_cache->c_data == 0) ||
		    ((grpdata = (Word *)_cache->c_data->d_buf) == 0))
			continue;
		grpcnt = shdr->sh_size / sizeof (Word);

		/*
		 * Get the data buffer for the associated symbol table and
		 * string table.
		 */
		if (stringtbl(cache, 1, scnt, shnum, file,
		    &symnum, &symsec, &strsec) == 0)
			return;

		syms = symsec->c_data->d_buf;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_GRP), _cache->c_name);
		dbg_print(0, MSG_INTL(MSG_GRP_TITLE));

		/*
		 * The first element of the group defines the group.  The
		 * associated symbol is defined by the sh_link field.
		 */
		if ((shdr->sh_info == SHN_UNDEF) || (shdr->sh_info > symnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHINFO),
			    file, _cache->c_name, EC_WORD(shdr->sh_info));
			return;
		}

		(void) strcpy(flgstrbuf, MSG_ORIG(MSG_STR_OSQBRKT));
		if (grpdata[0] & GRP_COMDAT) {
			(void) strcat(flgstrbuf, MSG_ORIG(MSG_GRP_COMDAT));
		}
		if ((unknown = (grpdata[0] & ~GRP_COMDAT)) != 0) {
			size_t	len = strlen(flgstrbuf);

			(void) snprintf(&flgstrbuf[len],
			    (MSG_GRP_COMDAT_SIZE + 10 - len),
			    MSG_ORIG(MSG_GRP_UNKNOWN), unknown);
		}
		(void) strcat(flgstrbuf, MSG_ORIG(MSG_STR_CSQBRKT));
		sym = (Sym *)(syms + shdr->sh_info);

		dbg_print(0, MSG_INTL(MSG_GRP_SIGNATURE), flgstrbuf,
		    demangle(string(_cache, 0, strsec, file, sym->st_name),
		    flags));

		for (gcnt = 1; gcnt < grpcnt; gcnt++) {
			char		index[MAXNDXSIZE];
			const char	*name;

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(gcnt));

			if (grpdata[gcnt] >= shnum)
				name = MSG_INTL(MSG_GRP_INVALSCN);
			else
				name = cache[grpdata[gcnt]].c_name;

			(void) printf(MSG_ORIG(MSG_GRP_ENTRY), index, name,
				EC_XWORD(grpdata[gcnt]));
		}
	}
}

static void
got(Cache *cache, Word shnum, Ehdr *ehdr, const char *file, uint_t flags)
{
	Cache		*gotcache = 0, *symtab = 0, *_cache;
	Addr		gotbgn, gotend;
	Shdr		*gotshdr;
	Word		cnt, gotents, gotndx;
	size_t		gentsize;
	Got_info	*gottable;
	char		*gotdata;
	Sym		*gotsym;
	Xword		gotsymaddr;

	/*
	 * First, find the got.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		_cache = &cache[cnt];
		if (strncmp(_cache->c_name, MSG_ORIG(MSG_ELF_GOT),
		    MSG_ELF_GOT_SIZE) == 0) {
			gotcache = _cache;
			break;
		}
	}
	if (gotcache == 0)
		return;

	/*
	 * A got section within a relocatable object is suspicious.
	 */
	if (ehdr->e_type == ET_REL) {
		(void) fprintf(stderr, MSG_INTL(MSG_GOT_UNEXPECTED), file,
		    _cache->c_name);
	}

	gotshdr = gotcache->c_shdr;
	if (gotshdr->sh_size == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, gotcache->c_name);
		return;
	}

	gotbgn = gotshdr->sh_addr;
	gotend = gotbgn + gotshdr->sh_size;

	/*
	 * Some architectures don't properly set the sh_entsize for the GOT
	 * table.  If it's not set, default to a size of a pointer.
	 */
	if ((gentsize = gotshdr->sh_entsize) == 0)
		gentsize = sizeof (Xword);

	/* LINTED */
	gotents = (Word)(gotshdr->sh_size / gentsize);
	gotdata = gotcache->c_data->d_buf;

	if ((gottable = calloc(gotents, sizeof (Got_info))) == 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC), file,
		    strerror(err));
		return;
	}

	/*
	 * Now we scan through all the sections looking for any relocations
	 * that may be against the GOT.  Since these may not be isolated to a
	 * .rel[a].got section we check them all.
	 * While scanning sections save the symbol table entry (a symtab
	 * overriding a dynsym) so that we can lookup _GLOBAL_OFFSET_TABLE_.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Word		type, symnum;
		Xword		relndx, relnum, relsize;
		void		*rels;
		Sym		*syms;
		Cache		*symsec, *strsec;
		Cache		*_cache = &cache[cnt];
		Shdr		*shdr;

		shdr = _cache->c_shdr;
		type = shdr->sh_type;

		if ((symtab == 0) && (type == SHT_DYNSYM)) {
			symtab = _cache;
			continue;
		}
		if (type == SHT_SYMTAB) {
			symtab = _cache;
			continue;
		}
		if ((type != SHT_RELA) && (type != SHT_REL))
			continue;

		/*
		 * Decide entry size.
		 */
		if (((relsize = shdr->sh_entsize) == 0) ||
		    (relsize > shdr->sh_size)) {
			if (type == SHT_RELA)
				relsize = sizeof (Rela);
			else
				relsize = sizeof (Rel);
		}

		/*
		 * Determine the number of relocations available.
		 */
		if (shdr->sh_size == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			continue;
		}
		rels = _cache->c_data->d_buf;
		relnum = shdr->sh_size / relsize;

		/*
		 * Get the data buffer for the associated symbol table and
		 * string table.
		 */
		if (stringtbl(cache, 1, cnt, shnum, file,
		    &symnum, &symsec, &strsec) == 0)
			continue;

		syms = symsec->c_data->d_buf;

		/*
		 * Loop through the relocation entries.
		 */
		for (relndx = 0; relndx < relnum; relndx++,
		    rels = (void *)((char *)rels + relsize)) {
			char		section[BUFSIZ];
			Addr		offset;
			Got_info	*gip;
			Word		symndx, reltype;
			Rela		*rela;
			Rel		*rel;

			/*
			 * Unravel the relocation.
			 */
			if (type == SHT_RELA) {
				rela = (Rela *)rels;
				symndx = ELF_R_SYM(rela->r_info);
				reltype = ELF_R_TYPE(rela->r_info);
				offset = rela->r_offset;
			} else {
				rel = (Rel *)rels;
				symndx = ELF_R_SYM(rel->r_info);
				reltype = ELF_R_TYPE(rel->r_info);
				offset = rel->r_offset;
			}

			/*
			 * Only pay attention to relocations against the GOT.
			 */
			if ((offset < gotbgn) || (offset > gotend))
				continue;

			/* LINTED */
			gotndx = (Word)((offset - gotbgn) /
			    gotshdr->sh_entsize);
			gip = &gottable[gotndx];

			if (gip->g_reltype != 0) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_GOT_MULTIPLE), file,
				    EC_WORD(gotndx), EC_ADDR(offset));
				continue;
			}

			if (symndx)
				gip->g_symname = relsymname(cache, _cache,
				    strsec, symndx, symnum, relndx, syms,
				    section, BUFSIZ, file, flags);
			gip->g_reltype = reltype;
			gip->g_rel = rels;
		}
	}

	if (symlookup(MSG_ORIG(MSG_GOT_SYM), cache, shnum, &gotsym, symtab,
	    file))
		gotsymaddr = gotsym->st_value;
	else
		gotsymaddr = gotbgn;

	dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(0, MSG_INTL(MSG_ELF_SCN_GOT), gotcache->c_name);
	Elf_got_title(0);

	for (gotndx = 0; gotndx < gotents; gotndx++) {
		Got_info	*gip;
		Sword		gindex;
		Addr		gaddr;
		Xword		gotentry;

		gip = &gottable[gotndx];

		gaddr = gotbgn + (gotndx * gentsize);
		gindex = (Sword)(gaddr - gotsymaddr) / (Sword)gentsize;

		if (gentsize == sizeof (Word))
			/* LINTED */
			gotentry = (Xword)(*((Word *)(gotdata) + gotndx));
		else
			/* LINTED */
			gotentry = *((Xword *)(gotdata) + gotndx);

		Elf_got_entry(0, gindex, gaddr, gotentry, ehdr->e_machine,
		    gip->g_reltype, gip->g_rel, gip->g_symname);
	}
	free(gottable);
}

void
checksum(Elf *elf)
{
	dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(0, MSG_INTL(MSG_STR_CHECKSUM), elf_checksum(elf));
}

void
regular(const char *file, Elf *elf, uint_t flags, char *Nname, int wfd)
{
	Elf_Scn		*scn;
	Ehdr		*ehdr;
	Elf_Data	*data;
	size_t		cnt, shstrndx, shnum, phnum;
	Shdr		*nameshdr, *shdr;
	char		*names = 0;
	Cache		*cache, *_cache;
	Cache		*versymcache = 0;

	if ((ehdr = elf_getehdr(elf)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETEHDR));
		return;
	}

	if (elf_getshnum(elf, &shnum) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHNUM));
		return;
	}

	if (elf_getshstrndx(elf, &shstrndx) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHSTRNDX));
		return;
	}

	if (elf_getphnum(elf, &phnum) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHNUM));
		return;
	}

	if ((scn = elf_getscn(elf, 0)) != NULL) {
		if ((shdr = elf_getshdr(scn)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN), 0);
			return;
		}
	} else
		shdr = 0;

	/*
	 * Print the elf header.
	 */
	if (flags & FLG_EHDR)
		Elf_ehdr(0, ehdr, shdr);

	/*
	 * Print the program headers.
	 */
	if ((flags & FLG_PHDR) && (phnum != 0)) {
		Phdr *phdr;

		if ((phdr = elf_getphdr(elf)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
			return;
		}

		for (cnt = 0; cnt < phnum; phdr++, cnt++) {
			dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(0, MSG_INTL(MSG_ELF_PHDR), EC_WORD(cnt));
			Elf_phdr(0, ehdr->e_machine, phdr);
		}
	}


	/*
	 * Return now if there are no section, if there's just one section to
	 * act as an extension of the ELF header, or if on section information
	 * was requested.
	 */
	if ((shnum <= 1) || (flags && (flags & ~(FLG_EHDR | FLG_PHDR)) == 0)) {
		if ((ehdr->e_type == ET_CORE) && (flags & FLG_NOTE))
			note(0, shnum, 0, file);
		return;
	}


	/*
	 * Obtain the .shstrtab data buffer to provide the required section
	 * name strings.
	 */
	if ((scn = elf_getscn(elf, shstrndx)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETSCN));
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SHDR),
		    EC_XWORD(shstrndx));

	} else if ((data = elf_getdata(scn, NULL)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETDATA));
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_DATA),
		    EC_XWORD(shstrndx));

	} else if ((nameshdr = elf_getshdr(scn)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN),
		    /* LINTED */
		    (int)elf_ndxscn(scn));

	} else if ((names = data->d_buf) == 0)
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_SHSTRNULL), file);

	/*
	 * Fill in the cache descriptor with information for each section.
	 */
	if ((cache = malloc(shnum * sizeof (Cache))) == 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    file, strerror(err));
		return;
	}

	*cache = cache_init;
	_cache = cache;
	_cache++;

	for (cnt = 1, scn = NULL; scn = elf_nextscn(elf, scn);
	    cnt++, _cache++) {
		if ((_cache->c_shdr = elf_getshdr(scn)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN),
			    /* LINTED */
			    (int)elf_ndxscn(scn));
		}

		if (names && _cache->c_shdr->sh_name &&
		    /* LINTED */
		    (nameshdr->sh_size > _cache->c_shdr->sh_name))
			_cache->c_name = names + _cache->c_shdr->sh_name;
		else {
			/*
			 * If there exists no shstrtab data, or a section header
			 * has no name (an invalid index of 0), then compose a
			 * name for each section.
			 */
			char	scnndxnm[100];

			(void) snprintf(scnndxnm, 100, MSG_INTL(MSG_FMT_SCNNDX),
			    cnt);

			/*
			 * Although we have a valid shstrtab section inform the
			 * user if this section name index exceeds the shstrtab
			 * data.
			 */
			if (names &&
			    /* LINTED */
			    (nameshdr->sh_size <= _cache->c_shdr->sh_name)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSHNAME), file,
				    _cache->c_name,
				    EC_XWORD(_cache->c_shdr->sh_name));
			}

			if ((_cache->c_name =
			    malloc(strlen(scnndxnm) + 1)) == 0) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
				    file, strerror(err));
				return;
			}
			(void) strcpy(_cache->c_name, scnndxnm);
		}

		if ((_cache->c_data = elf_getdata(scn, NULL)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETDATA));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCNDATA),
			    /* LINTED */
			    (int)elf_ndxscn(scn));
		}

		/*
		 * Do we wish to write the section out?
		 */
		if (wfd && Nname && (strcmp(Nname, _cache->c_name) == 0)) {
			(void) write(wfd, _cache->c_data->d_buf,
			    _cache->c_data->d_size);
		}
	}

	if (flags & FLG_SHDR)
		sections(file, cache, shnum, ehdr, Nname);

	if (flags & FLG_INTERP)
		interp(file, cache, shnum, phnum, elf);

	versymcache = versions(cache, shnum, file, flags);

	if (flags & FLG_SYMBOLS)
		symbols(cache, shnum, ehdr, Nname, versymcache, file, flags);

	if (flags & FLG_HASH)
		hash(cache, shnum, Nname, file, flags);

	if (flags & FLG_GOT)
		got(cache, shnum, ehdr, file, flags);

	if (flags & FLG_GROUP)
		group(cache, shnum, Nname, file, flags);

	if (flags & FLG_SYMINFO)
		syminfo(cache, shnum, file);

	if (flags & FLG_RELOC)
		reloc(cache, shnum, ehdr, Nname, file, flags);

	if (flags & FLG_DYNAMIC)
		dynamic(cache, shnum, ehdr, file);

	if (flags & FLG_NOTE)
		note(cache, shnum, Nname, file);

	if (flags & FLG_MOVE)
		move(cache, shnum, Nname, file, flags);

	if (flags & FLG_CHECKSUM)
		checksum(elf);

	if (flags & FLG_CAP)
		cap(file, cache, shnum, phnum, ehdr, elf);

	if (flags & FLG_UNWIND)
		unwind(cache, shnum, phnum, ehdr, Nname, file, elf);

	free(cache);
}
