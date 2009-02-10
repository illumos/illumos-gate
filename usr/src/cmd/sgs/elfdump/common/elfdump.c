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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Dump an elf file.
 */
#include	<sys/elf_386.h>
#include	<sys/elf_amd64.h>
#include	<sys/elf_SPARC.h>
#include	<_libelf.h>
#include	<dwarf.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<errno.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<msg.h>
#include	<_elfdump.h>


/*
 * VERSYM_STATE is used to maintain information about the VERSYM section
 * in the object being analyzed. It is filled in by versions(), and used
 * by init_symtbl_state() when displaying symbol information.
 *
 * There are three forms of symbol versioning known to us:
 *
 * 1) The original form, introduced with Solaris 2.5, in which
 *	the Versym contains indexes to Verdef records, and the
 *	Versym values for UNDEF symbols resolved by other objects
 *	are all set to 0.
 * 2) The GNU form, which is backward compatible with the original
 *	Solaris form, but which adds several extensions:
 *	- The Versym also contains indexes to Verneed records, recording
 *		which object/version contributed the external symbol at
 *		link time. These indexes start with the next value following
 *		the final Verdef index. The index is written to the previously
 *		reserved vna_other field of the ELF Vernaux structure.
 *	- The top bit of the Versym value is no longer part of the index,
 *		but is used as a "hidden bit" to prevent binding to the symbol.
 *	- Multiple implementations of a given symbol, contained in varying
 *		versions are allowed, using special assembler pseudo ops,
 *		and encoded in the symbol name using '@' characters.
 * 3) Modified Solaris form, in which we adopt the first GNU extension
 *	(Versym indexes to Verneed records), but not the others.
 *
 * elfdump can handle any of these cases. The presence of a DT_VERSYM
 * dynamic element indicates a full GNU object. An object that lacks
 * a DT_VERSYM entry, but which has non-zero vna_other fields in the Vernaux
 * structures is a modified Solaris object. An object that has neither of
 * these uses the original form.
 *
 * max_verndx contains the largest version index that can appear
 * in a Versym entry. This can never be less than 1: In the case where
 * there is no verdef/verneed sections, the [0] index is reserved
 * for local symbols, and the [1] index for globals. If the original
 * Solaris versioning rules are in effect and there is a verdef section,
 * then max_verndex is the number of defined versions. If one of the
 * other versioning forms is in effect, then:
 *	1) If there is no verneed section, it is the same as for
 *		original Solaris versioning.
 *	2) If there is a verneed section, the vna_other field of the
 *		Vernaux structs contain versions, and max_verndx is the
 *		largest such index.
 *
 * If gnu_full is True, the object uses the full GNU form of versioning.
 * The value of the gnu_full field is based on the presence of
 * a DT_VERSYM entry in the dynamic section: GNU ld produces these, and
 * Solaris ld does not.
 *
 * The gnu_needed field is True if the Versym contains indexes to
 * Verneed records, as indicated by non-zero vna_other fields in the Verneed
 * section. If gnu_full is True, then gnu_needed will always be true.
 * However, gnu_needed can be true without gnu_full. This is the modified
 * Solaris form.
 */
typedef struct {
	Cache	*cache;		/* Pointer to cache entry for VERSYM */
	Versym	*data;		/* Pointer to versym array */
	int	gnu_full;	/* True if object uses GNU versioning rules */
	int	gnu_needed;	/* True if object uses VERSYM indexes for */
				/*	VERNEED (subset of gnu_full) */
	int	max_verndx;	/* largest versym index value */
} VERSYM_STATE;

/*
 * SYMTBL_STATE is used to maintain information about a single symbol
 * table section, for use by the routines that display symbol information.
 */
typedef struct {
	const char	*file;		/* Name of file */
	Ehdr		*ehdr;		/* ELF header for file */
	Cache		*cache;		/* Cache of all section headers */
	Word		shnum;		/* # of sections in cache */
	Cache		*seccache;	/* Cache of symbol table section hdr */
	Word		secndx;		/* Index of symbol table section hdr */
	const char	*secname;	/* Name of section */
	uint_t		flags;		/* Command line option flags */
	struct {			/* Extended section index data */
		int	checked;	/* TRUE if already checked for shxndx */
		Word	*data;		/* NULL, or extended section index */
					/*	used for symbol table entries */
		uint_t	n;		/* # items in shxndx.data */
	} shxndx;
	VERSYM_STATE	*versym;	/* NULL, or associated VERSYM section */
	Sym 		*sym;		/* Array of symbols */
	Word		symn;		/* # of symbols */
} SYMTBL_STATE;



/*
 * Focal point for verifying symbol names.
 */
static const char *
string(Cache *refsec, Word ndx, Cache *strsec, const char *file, Word name)
{
	/*
	 * If an error in this routine is due to a property of the string
	 * section, as opposed to a bad offset into the section (a property of
	 * the referencing section), then we will detect the same error on
	 * every call involving those sections. We use these static variables
	 * to retain the information needed to only issue each such error once.
	 */
	static Cache	*last_refsec;	/* Last referencing section seen */
	static int	strsec_err;	/* True if error issued */

	const char	*strs;
	Word		strn;

	if (strsec->c_data == NULL)
		return (NULL);

	strs = (char *)strsec->c_data->d_buf;
	strn = strsec->c_data->d_size;

	/*
	 * We only print a diagnostic regarding a bad string table once per
	 * input section being processed. If the refsec has changed, reset
	 * our retained error state.
	 */
	if (last_refsec != refsec) {
		last_refsec = refsec;
		strsec_err = 0;
	}

	/* Verify that strsec really is a string table */
	if (strsec->c_shdr->sh_type != SHT_STRTAB) {
		if (!strsec_err) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_NOTSTRTAB),
			    file, strsec->c_ndx, refsec->c_ndx);
			strsec_err = 1;
		}
		return (MSG_INTL(MSG_STR_UNKNOWN));
	}

	/*
	 * Is the string table offset within range of the available strings?
	 */
	if (name >= strn) {
		/*
		 * Do we have a empty string table?
		 */
		if (strs == 0) {
			if (!strsec_err) {
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
				    file, strsec->c_name);
				strsec_err = 1;
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
    Word relndx, Sym *syms, char *secstr, size_t secsz, const char *file)
{
	Sym		*sym;
	const char	*name;

	if (symndx >= symnum) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_RELBADSYMNDX),
		    file, EC_WORD(symndx), EC_WORD(relndx));
		return (MSG_INTL(MSG_STR_UNKNOWN));
	}

	sym = (Sym *)(syms + symndx);
	name = string(csec, symndx, strsec, file, sym->st_name);

	/*
	 * If the symbol represents a section offset construct an appropriate
	 * string.  Note, although section symbol table entries typically have
	 * a NULL name pointer, entries do exist that point into the string
	 * table to their own NULL strings.
	 */
	if ((ELF_ST_TYPE(sym->st_info) == STT_SECTION) &&
	    ((sym->st_name == 0) || (*name == '\0'))) {
		(void) snprintf(secstr, secsz, MSG_INTL(MSG_STR_SECTION),
		    cache[sym->st_shndx].c_name);
		return ((const char *)secstr);
	}

	return (name);
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
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, cache[ndx].c_name);
			return (0);
		}

		/*
		 * Obtain, and verify the symbol table data.
		 */
		if ((cache[ndx].c_data == NULL) ||
		    (cache[ndx].c_data->d_buf == NULL)) {
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
	if (symtab->c_data == NULL)
		return (0);

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
sections(const char *file, Cache *cache, Word shnum, Ehdr *ehdr)
{
	size_t	seccnt;

	for (seccnt = 1; seccnt < shnum; seccnt++) {
		Cache		*_cache = &cache[seccnt];
		Shdr		*shdr = _cache->c_shdr;
		const char	*secname = _cache->c_name;

		/*
		 * Although numerous section header entries can be zero, it's
		 * usually a sign of trouble if the type is zero.
		 */
		if (shdr->sh_type == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHTYPE),
			    file, secname, EC_WORD(shdr->sh_type));
		}

		if (!match(MATCH_F_ALL, secname, seccnt, shdr->sh_type))
			continue;

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
unwind(Cache *cache, Word shnum, Word phnum, Ehdr *ehdr, const char *file,
    Elf *elf)
{
	Conv_dwarf_ehe_buf_t	dwarf_ehe_buf;
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

		if (!match(MATCH_F_ALL, _cache->c_name, cnt, shdr->sh_type))
			continue;

		if (_cache->c_data == NULL)
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
			    conv_dwarf_ehe(frame_ptr_enc, &dwarf_ehe_buf),
			    EC_XWORD(frame_ptr));

			fde_cnt = dwarf_ehe_extract(data, &ndx, fde_cnt_enc,
			    ehdr->e_ident, shdr->sh_addr + ndx);

			dbg_print(0, MSG_ORIG(MSG_UNW_FDCNENC),
			    conv_dwarf_ehe(fde_cnt_enc, &dwarf_ehe_buf),
			    EC_XWORD(fde_cnt));
			dbg_print(0, MSG_ORIG(MSG_UNW_TABENC),
			    conv_dwarf_ehe(table_enc, &dwarf_ehe_buf));
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
			uint_t		cieid, cielength, cieversion;
			uint_t		cieretaddr;
			int		cieRflag, cieLflag, ciePflag, cieZflag;
			uint_t		cieaugndx, length, id;
			uint64_t	ciecalign, ciedalign;
			char		*cieaugstr;

			ndx = 0;
			/*
			 * Extract length in lsb format.  A zero length
			 * indicates that this CIE is a terminator and that
			 * processing for this unwind information should end.
			 * However, skip this entry and keep processing, just
			 * in case there is any other information remaining in
			 * this section.  Note, ld(1) will terminate the
			 * processing of the .eh_frame contents for this file
			 * after a zero length CIE, thus any information that
			 * does follow is ignored by ld(1), and is therefore
			 * questionable.
			 */
			if ((length = LSB32EXTRACT(data + off + ndx)) == 0) {
				dbg_print(0, MSG_ORIG(MSG_UNW_ZEROTERM));
				off += 4;
				continue;
			}
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
					dbg_print(0,
					    MSG_ORIG(MSG_UNW_CIEAXVAL));

				for (cieaugndx = 0; cieaugstr[cieaugndx];
				    cieaugndx++) {
					uint_t	val;

					switch (cieaugstr[cieaugndx]) {
					case 'z':
						val = uleb_extract(&data[off],
						    &ndx);
						dbg_print(0,
						    MSG_ORIG(MSG_UNW_CIEAXSIZ),
						    val);
						cieZflag = 1;
						break;
					case 'P':
						ciePflag = data[off + ndx];
						ndx += 1;

						persVal = dwarf_ehe_extract(
						    &data[off], &ndx, ciePflag,
						    ehdr->e_ident,
						    shdr->sh_addr + off + ndx);
						dbg_print(0,
						    MSG_ORIG(MSG_UNW_CIEAXPERS),
						    ciePflag,
						    conv_dwarf_ehe(ciePflag,
						    &dwarf_ehe_buf),
						    EC_XWORD(persVal));
						break;
					case 'R':
						val = data[off + ndx];
						ndx += 1;
						dbg_print(0,
						    MSG_ORIG(MSG_UNW_CIEAXCENC),
						    val, conv_dwarf_ehe(val,
						    &dwarf_ehe_buf));
						cieRflag = val;
						break;
					case 'L':
						val = data[off + ndx];
						ndx += 1;
						dbg_print(0,
						    MSG_ORIG(MSG_UNW_CIEAXLSDA),
						    val, conv_dwarf_ehe(val,
						    &dwarf_ehe_buf));
						cieLflag = val;
						break;
					default:
						dbg_print(0,
						    MSG_ORIG(MSG_UNW_CIEAXUNEC),
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
					    MSG_ORIG(MSG_UNW_FDEAXVAL));
				if (cieZflag) {
					uint64_t    val;
					val = uleb_extract(&data[off], &ndx);
					dbg_print(0,
					    MSG_ORIG(MSG_UNW_FDEAXSIZE),
					    EC_XWORD(val));
					if (val & cieLflag) {
						fdeinitloc = dwarf_ehe_extract(
						    &data[off], &ndx, cieLflag,
						    ehdr->e_ident,
						    shdr->sh_addr + off + ndx);
						dbg_print(0,
						    MSG_ORIG(MSG_UNW_FDEAXLSDA),
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
	Shdr		*cshdr = NULL;
	Cache		*ccache;
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

		if (_cache->c_data == NULL)
			continue;

		ccache = _cache;
		cshdr = shdr;
		break;
	}

	if ((cshdr == NULL) && (cphdr_off == 0))
		return;

	/*
	 * Print the hardware/software capabilities section.
	 */
	if (cshdr) {
		Word	ndx, capn;
		Cap	*cap = (Cap *)ccache->c_data->d_buf;

		if ((cshdr->sh_entsize == 0) || (cshdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, ccache->c_name);
			return;
		}

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_CAP), ccache->c_name);

		Elf_cap_title(0);

		capn = (Word)(cshdr->sh_size / cshdr->sh_entsize);

		for (ndx = 0; ndx < capn; cap++, ndx++) {
			if (cap->c_tag == CA_SUNW_NULL)
				continue;

			Elf_cap_entry(0, cap, ndx, ehdr->e_machine);

			/*
			 * An SF1_SUNW_ADDR32 software capability in a 32-bit
			 * object is suspicious as it has no effect.
			 */
			if ((cap->c_tag == CA_SUNW_SF_1) &&
			    (ehdr->e_ident[EI_CLASS] == ELFCLASS32) &&
			    (cap->c_un.c_val & SF1_SUNW_ADDR32)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_WARN_INADDR32SF1),
				    file, ccache->c_name);
			}
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
	if (ishdr && icache->c_data) {
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
	if (infocache->c_data == NULL)
		return;

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
	if (cache[infoshdr->sh_info].c_data == NULL)
		return;

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
version_def(Verdef *vdf, Word vdf_num, Cache *vcache, Cache *scache,
    const char *file)
{
	Word	cnt;
	char	index[MAXNDXSIZE];

	Elf_ver_def_title(0);

	for (cnt = 1; cnt <= vdf_num; cnt++,
	    vdf = (Verdef *)((uintptr_t)vdf + vdf->vd_next)) {
		Conv_ver_flags_buf_t	ver_flags_buf;
		const char		*name, *dep;
		Half			vcnt = vdf->vd_cnt - 1;
		Half			ndx = vdf->vd_ndx;
		Verdaux	*vdap = (Verdaux *)((uintptr_t)vdf + vdf->vd_aux);

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
		    conv_ver_flags(vdf->vd_flags, 0, &ver_flags_buf));

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
 * Print version needed section entries.
 *
 * entry:
 *	vnd - Address of verneed data
 *	vnd_num - # of Verneed entries
 *	vcache - Cache of verneed section being processed
 *	scache - Cache of associated string table section
 *	file - Name of object being processed.
 *	versym - Information about versym section
 *
 * exit:
 *	The versions have been printed. If GNU style versioning
 *	is in effect, versym->max_verndx has been updated to
 *	contain the largest version index seen.
 *
 * note:
 * 	The versym section of an object that follows the original
 *	Solaris versioning rules only contains indexes into the verdef
 *	section. Symbols defined in other objects (UNDEF) are given
 *	a version of 0, indicating that they are not defined by
 *	this file, and the Verneed entries do not have associated version
 *	indexes. For these reasons, we do not display a version index
 *	for original-style Verneed sections.
 *
 *	The GNU versioning extensions alter this: Symbols defined in other
 *	objects receive a version index in the range above those defined
 *	by the Verdef section, and the vna_other field of the Vernaux
 *	structs inside the Verneed section contain the version index for
 *	that item. We therefore  display the index when showing the
 *	contents of a GNU style Verneed section. You should not
 *	necessarily expect these indexes to appear in sorted
 *	order --- it seems that the GNU ld assigns the versions as
 *	symbols are encountered during linking, and then the results
 *	are assembled into the Verneed section afterwards.
 */
static void
version_need(Verneed *vnd, Word vnd_num, Cache *vcache, Cache *scache,
    const char *file, VERSYM_STATE *versym)
{
	Word		cnt;
	char		index[MAXNDXSIZE];
	const char	*index_str;

	Elf_ver_need_title(0, versym->gnu_needed);

	for (cnt = 1; cnt <= vnd_num; cnt++,
	    vnd = (Verneed *)((uintptr_t)vnd + vnd->vn_next)) {
		Conv_ver_flags_buf_t	ver_flags_buf;
		const char		*name, *dep;
		Half			vcnt = vnd->vn_cnt;
		Vernaux *vnap = (Vernaux *)((uintptr_t)vnd + vnd->vn_aux);

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

		if (vnap->vna_other == 0) {	/* Traditional form */
			index_str = MSG_ORIG(MSG_STR_EMPTY);
		} else {			/* GNU form */
			index_str = index;
			/* Format the version index value */
			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(vnap->vna_other));
			if (vnap->vna_other > versym->max_verndx)
				versym->max_verndx = vnap->vna_other;
		}
		Elf_ver_line_1(0, index_str, name, dep,
		    conv_ver_flags(vnap->vna_flags, 0, &ver_flags_buf));

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
				if (vnap->vna_other > 0) {
					/* Format the next index value */
					(void) snprintf(index, MAXNDXSIZE,
					    MSG_ORIG(MSG_FMT_INDEX),
					    EC_XWORD(vnap->vna_other));
					Elf_ver_line_1(0, index,
					    MSG_ORIG(MSG_STR_EMPTY), dep,
					    conv_ver_flags(vnap->vna_flags,
					    0, &ver_flags_buf));
					if (vnap->vna_other >
					    versym->max_verndx)
						versym->max_verndx =
						    vnap->vna_other;
				} else {
					Elf_ver_line_3(0,
					    MSG_ORIG(MSG_STR_EMPTY), dep,
					    conv_ver_flags(vnap->vna_flags,
					    0, &ver_flags_buf));
				}
			}
		}
	}
}

/*
 * Examine the Verneed section for information related to GNU
 * style Versym indexing:
 *	- A non-zero vna_other field indicates that Versym indexes can
 *		reference Verneed records.
 *	- If the object uses GNU style Versym indexing, the
 *	  maximum index value is needed to detect bad Versym entries.
 *
 * entry:
 *	vnd - Address of verneed data
 *	vnd_num - # of Verneed entries
 *	versym - Information about versym section
 *
 * exit:
 *	If a non-zero vna_other field is seen, versym->gnu_needed is set.
 *
 *	versym->max_verndx has been updated to contain the largest
 *	version index seen.
 */
static void
update_gnu_verndx(Verneed *vnd, Word vnd_num, VERSYM_STATE *versym)
{
	Word		cnt;

	for (cnt = 1; cnt <= vnd_num; cnt++,
	    vnd = (Verneed *)((uintptr_t)vnd + vnd->vn_next)) {
		Half	vcnt = vnd->vn_cnt;
		Vernaux	*vnap = (Vernaux *)((uintptr_t)vnd + vnd->vn_aux);

		/*
		 * A non-zero value of vna_other indicates that this
		 * object references VERNEED items from the VERSYM
		 * array.
		 */
		if (vnap->vna_other != 0) {
			versym->gnu_needed = 1;
			if (vnap->vna_other > versym->max_verndx)
				versym->max_verndx = vnap->vna_other;
		}

		/*
		 * Check any additional version dependencies.
		 */
		if (vcnt) {
			vnap = (Vernaux *)((uintptr_t)vnap + vnap->vna_next);
			for (vcnt--; vcnt; vcnt--,
			    vnap = (Vernaux *)((uintptr_t)vnap +
			    vnap->vna_next)) {
				if (vnap->vna_other == 0)
					continue;

				versym->gnu_needed = 1;
				if (vnap->vna_other > versym->max_verndx)
					versym->max_verndx = vnap->vna_other;
			}
		}
	}
}

/*
 * Display version section information if the flags require it.
 * Return version information needed by other output.
 *
 * entry:
 *	cache - Cache of all section headers
 *	shnum - # of sections in cache
 *	file - Name of file
 *	flags - Command line option flags
 *	versym - VERSYM_STATE block to be filled in.
 */
static void
versions(Cache *cache, Word shnum, const char *file, uint_t flags,
    VERSYM_STATE *versym)
{
	GElf_Word	cnt;
	Cache		*verdef_cache = NULL, *verneed_cache = NULL;


	/* Gather information about the version sections */
	bzero(versym, sizeof (*versym));
	versym->max_verndx = 1;
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache		*_cache = &cache[cnt];
		Shdr		*shdr = _cache->c_shdr;
		Dyn		*dyn;
		ulong_t		numdyn;

		switch (shdr->sh_type) {
		case SHT_DYNAMIC:
			/*
			 * The GNU ld puts a DT_VERSYM entry in the dynamic
			 * section so that the runtime linker can use it to
			 * implement their versioning rules. They allow multiple
			 * incompatible functions with the same name to exist
			 * in different versions. The Solaris ld does not
			 * support this mechanism, and as such, does not
			 * produce DT_VERSYM. We use this fact to determine
			 * which ld produced this object, and how to interpret
			 * the version values.
			 */
			if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0) ||
			    (_cache->c_data == NULL))
				continue;
			numdyn = shdr->sh_size / shdr->sh_entsize;
			dyn = (Dyn *)_cache->c_data->d_buf;
			for (; numdyn-- > 0; dyn++)
				if (dyn->d_tag == DT_VERSYM) {
					versym->gnu_full =
					    versym->gnu_needed = 1;
					break;
				}
			break;

		case SHT_SUNW_versym:
			/* Record data address for later symbol processing */
			if (_cache->c_data != NULL) {
				versym->cache = _cache;
				versym->data = _cache->c_data->d_buf;
				continue;
			}
			break;

		case SHT_SUNW_verdef:
		case SHT_SUNW_verneed:
			/*
			 * Ensure the data is non-NULL and the number
			 * of items is non-zero. Otherwise, we don't
			 * understand the section, and will not use it.
			 */
			if ((_cache->c_data == NULL) ||
			    (_cache->c_data->d_buf == NULL)) {
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
				    file, _cache->c_name);
				continue;
			}
			if (shdr->sh_info == 0) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSHINFO),
				    file, _cache->c_name,
				    EC_WORD(shdr->sh_info));
				continue;
			}

			/* Make sure the string table index is in range */
			if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSHLINK), file,
				    _cache->c_name, EC_WORD(shdr->sh_link));
				continue;
			}

			/*
			 * The section is usable. Save the cache entry.
			 */
			if (shdr->sh_type == SHT_SUNW_verdef) {
				verdef_cache = _cache;
				/*
				 * Under Solaris rules, if there is a verdef
				 * section, the max versym index is number
				 * of version definitions it supplies.
				 */
				versym->max_verndx = shdr->sh_info;
			} else {
				verneed_cache = _cache;
			}
			break;
		}
	}

	/*
	 * If there is a Verneed section, examine it for information
	 * related to GNU style versioning.
	 */
	if (verneed_cache != NULL)
		update_gnu_verndx((Verneed *)verneed_cache->c_data->d_buf,
		    verneed_cache->c_shdr->sh_info, versym);

	/*
	 * Now that all the information is available, display the
	 * Verdef and Verneed section contents, if requested.
	 */
	if ((flags & FLG_SHOW_VERSIONS) == 0)
		return;
	if (verdef_cache != NULL) {
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_VERDEF),
		    verdef_cache->c_name);
		version_def((Verdef *)verdef_cache->c_data->d_buf,
		    verdef_cache->c_shdr->sh_info, verdef_cache,
		    &cache[verdef_cache->c_shdr->sh_link], file);
	}
	if (verneed_cache != NULL) {
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_VERNEED),
		    verneed_cache->c_name);
		/*
		 * If GNU versioning applies to this object, version_need()
		 * will update versym->max_verndx, and it is not
		 * necessary to call update_gnu_verndx().
		 */
		version_need((Verneed *)verneed_cache->c_data->d_buf,
		    verneed_cache->c_shdr->sh_info, verneed_cache,
		    &cache[verneed_cache->c_shdr->sh_link], file, versym);
	}
}

/*
 * Initialize a symbol table state structure
 *
 * entry:
 *	state - State structure to be initialized
 *	cache - Cache of all section headers
 *	shnum - # of sections in cache
 *	secndx - Index of symbol table section
 *	ehdr - ELF header for file
 *	versym - Information about versym section
 *	file - Name of file
 *	flags - Command line option flags
 */
static int
init_symtbl_state(SYMTBL_STATE *state, Cache *cache, Word shnum, Word secndx,
    Ehdr *ehdr, VERSYM_STATE *versym, const char *file, uint_t flags)
{
	Shdr *shdr;

	state->file = file;
	state->ehdr = ehdr;
	state->cache = cache;
	state->shnum = shnum;
	state->seccache = &cache[secndx];
	state->secndx = secndx;
	state->secname = state->seccache->c_name;
	state->flags = flags;
	state->shxndx.checked = 0;
	state->shxndx.data = NULL;
	state->shxndx.n = 0;

	shdr = state->seccache->c_shdr;

	/*
	 * Check the symbol data and per-item size.
	 */
	if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, state->secname);
		return (0);
	}
	if (state->seccache->c_data == NULL)
		return (0);

	/* LINTED */
	state->symn = (Word)(shdr->sh_size / shdr->sh_entsize);
	state->sym = (Sym *)state->seccache->c_data->d_buf;

	/*
	 * Check associated string table section.
	 */
	if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
		    file, state->secname, EC_WORD(shdr->sh_link));
		return (0);
	}

	/*
	 * Determine if there is a associated Versym section
	 * with this Symbol Table.
	 */
	if (versym->cache &&
	    (versym->cache->c_shdr->sh_link == state->secndx))
		state->versym = versym;
	else
		state->versym = NULL;


	return (1);
}

/*
 * Determine the extended section index used for symbol tables entries.
 */
static void
symbols_getxindex(SYMTBL_STATE *state)
{
	uint_t	symn;
	Word	symcnt;

	state->shxndx.checked = 1;   /* Note that we've been called */
	for (symcnt = 1; symcnt < state->shnum; symcnt++) {
		Cache	*_cache = &state->cache[symcnt];
		Shdr	*shdr = _cache->c_shdr;

		if ((shdr->sh_type != SHT_SYMTAB_SHNDX) ||
		    (shdr->sh_link != state->secndx))
			continue;

		if ((shdr->sh_entsize) &&
		    /* LINTED */
		    ((symn = (uint_t)(shdr->sh_size / shdr->sh_entsize)) == 0))
			continue;

		if (_cache->c_data == NULL)
			continue;

		state->shxndx.data = _cache->c_data->d_buf;
		state->shxndx.n = symn;
		return;
	}
}

/*
 * Produce a line of output for the given symbol
 *
 * entry:
 *	state - Symbol table state
 *	symndx - Index of symbol within the table
 *	info - Value of st_info (indicates local/global range)
 *	symndx_disp - Index to display. This may not be the same
 *		as symndx if the display is relative to the logical
 *		combination of the SUNW_ldynsym/dynsym tables.
 *	sym - Symbol to display
 */
static void
output_symbol(SYMTBL_STATE *state, Word symndx, Word info, Word disp_symndx,
    Sym *sym)
{
	/*
	 * Symbol types for which we check that the specified
	 * address/size land inside the target section.
	 */
	static const int addr_symtype[STT_NUM] = {
		0,			/* STT_NOTYPE */
		1,			/* STT_OBJECT */
		1,			/* STT_FUNC */
		0,			/* STT_SECTION */
		0,			/* STT_FILE */
		1,			/* STT_COMMON */
		0,			/* STT_TLS */
	};
#if STT_NUM != (STT_TLS + 1)
#error "STT_NUM has grown. Update addr_symtype[]"
#endif

	char		index[MAXNDXSIZE];
	const char	*symname, *sec;
	Versym		verndx;
	int		gnuver;
	uchar_t		type;
	Shdr		*tshdr;
	Word		shndx;
	Conv_inv_buf_t	inv_buf;

	/* Ensure symbol index is in range */
	if (symndx >= state->symn) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSORTNDX),
		    state->file, state->secname, EC_WORD(symndx));
		return;
	}

	/*
	 * If we are using extended symbol indexes, find the
	 * corresponding SHN_SYMTAB_SHNDX table.
	 */
	if ((sym->st_shndx == SHN_XINDEX) && (state->shxndx.checked == 0))
		symbols_getxindex(state);

	/* LINTED */
	symname = string(state->seccache, symndx,
	    &state->cache[state->seccache->c_shdr->sh_link], state->file,
	    sym->st_name);

	tshdr = 0;
	sec = NULL;

	if (state->ehdr->e_type == ET_CORE) {
		sec = (char *)MSG_INTL(MSG_STR_UNKNOWN);
	} else if (state->flags & FLG_CTL_FAKESHDR) {
		/*
		 * If we are using fake section headers derived from
		 * the program headers, then the section indexes
		 * in the symbols do not correspond to these headers.
		 * The section names are not available, so all we can
		 * do is to display them in numeric form.
		 */
		sec = conv_sym_shndx(sym->st_shndx, &inv_buf);
	} else if ((sym->st_shndx < SHN_LORESERVE) &&
	    (sym->st_shndx < state->shnum)) {
		shndx = sym->st_shndx;
		tshdr = state->cache[shndx].c_shdr;
		sec = state->cache[shndx].c_name;
	} else if (sym->st_shndx == SHN_XINDEX) {
		if (state->shxndx.data) {
			Word	_shxndx;

			if (symndx > state->shxndx.n) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYMXINDEX1),
				    state->file, state->secname,
				    EC_WORD(symndx));
			} else if ((_shxndx =
			    state->shxndx.data[symndx]) > state->shnum) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYMXINDEX2),
				    state->file, state->secname,
				    EC_WORD(symndx), EC_WORD(_shxndx));
			} else {
				shndx = _shxndx;
				tshdr = state->cache[shndx].c_shdr;
				sec = state->cache[shndx].c_name;
			}
		} else {
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_BADSYMXINDEX3),
			    state->file, state->secname, EC_WORD(symndx));
		}
	} else if ((sym->st_shndx < SHN_LORESERVE) &&
	    (sym->st_shndx >= state->shnum)) {
		(void) fprintf(stderr,
		    MSG_INTL(MSG_ERR_BADSYM5), state->file,
		    state->secname, EC_WORD(symndx),
		    demangle(symname, state->flags), sym->st_shndx);
	}

	/*
	 * If versioning is available display the
	 * version index. If not, then use 0.
	 */
	if (state->versym) {
		Versym test_verndx;

		verndx = test_verndx = state->versym->data[symndx];
		gnuver = state->versym->gnu_full;

		/*
		 * Check to see if this is a defined symbol with a
		 * version index that is outside the valid range for
		 * the file. The interpretation of this depends on
		 * the style of versioning used by the object.
		 *
		 * Versions >= VER_NDX_LORESERVE have special meanings,
		 * and are exempt from this checking.
		 *
		 * GNU style version indexes use the top bit of the
		 * 16-bit index value (0x8000) as the "hidden bit".
		 * We must mask off this bit in order to compare
		 * the version against the maximum value.
		 */
		if (gnuver)
			test_verndx &= ~0x8000;

		if ((test_verndx > state->versym->max_verndx) &&
		    (verndx < VER_NDX_LORESERVE))
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADVER),
			    state->file, state->secname, EC_WORD(symndx),
			    EC_HALF(test_verndx), state->versym->max_verndx);
	} else {
		verndx = 0;
		gnuver = 0;
	}

	/*
	 * Error checking for TLS.
	 */
	type = ELF_ST_TYPE(sym->st_info);
	if (type == STT_TLS) {
		if (tshdr &&
		    (sym->st_shndx != SHN_UNDEF) &&
		    ((tshdr->sh_flags & SHF_TLS) == 0)) {
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_BADSYM3), state->file,
			    state->secname, EC_WORD(symndx),
			    demangle(symname, state->flags));
		}
	} else if ((type != STT_SECTION) && sym->st_size &&
	    tshdr && (tshdr->sh_flags & SHF_TLS)) {
		(void) fprintf(stderr,
		    MSG_INTL(MSG_ERR_BADSYM4), state->file,
		    state->secname, EC_WORD(symndx),
		    demangle(symname, state->flags));
	}

	/*
	 * If a symbol with non-zero size has a type that
	 * specifies an address, then make sure the location
	 * it references is actually contained within the
	 * section.  UNDEF symbols don't count in this case,
	 * so we ignore them.
	 *
	 * The meaning of the st_value field in a symbol
	 * depends on the type of object. For a relocatable
	 * object, it is the offset within the section.
	 * For sharable objects, it is the offset relative to
	 * the base of the object, and for other types, it is
	 * the virtual address. To get an offset within the
	 * section for non-ET_REL files, we subtract the
	 * base address of the section.
	 */
	if (addr_symtype[type] && (sym->st_size > 0) &&
	    (sym->st_shndx != SHN_UNDEF) && ((sym->st_shndx < SHN_LORESERVE) ||
	    (sym->st_shndx == SHN_XINDEX)) && (tshdr != NULL)) {
		Word v = sym->st_value;
			if (state->ehdr->e_type != ET_REL)
				v -= tshdr->sh_addr;
		if (((v + sym->st_size) > tshdr->sh_size)) {
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_BADSYM6), state->file,
			    state->secname, EC_WORD(symndx),
			    demangle(symname, state->flags),
			    EC_WORD(shndx), EC_XWORD(tshdr->sh_size),
			    EC_XWORD(sym->st_value), EC_XWORD(sym->st_size));
		}
	}

	/*
	 * A typical symbol table uses the sh_info field to indicate one greater
	 * than the symbol table index of the last local symbol, STB_LOCAL.
	 * Therefore, symbol indexes less than sh_info should have local
	 * binding.  Symbol indexes greater than, or equal to sh_info, should
	 * have global binding.  Note, we exclude UNDEF/NOTY symbols with zero
	 * value and size, as these symbols may be the result of an mcs(1)
	 * section deletion.
	 */
	if (info) {
		uchar_t	bind = ELF_ST_BIND(sym->st_info);

		if ((symndx < info) && (bind != STB_LOCAL)) {
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_BADSYM7), state->file,
			    state->secname, EC_WORD(symndx),
			    demangle(symname, state->flags), EC_XWORD(info));

		} else if ((symndx >= info) && (bind == STB_LOCAL) &&
		    ((sym->st_shndx != SHN_UNDEF) ||
		    (ELF_ST_TYPE(sym->st_info) != STT_NOTYPE) ||
		    (sym->st_size != 0) || (sym->st_value != 0))) {
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_BADSYM8), state->file,
			    state->secname, EC_WORD(symndx),
			    demangle(symname, state->flags), EC_XWORD(info));
		}
	}

	(void) snprintf(index, MAXNDXSIZE,
	    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(disp_symndx));
	Elf_syms_table_entry(0, ELF_DBG_ELFDUMP, index,
	    state->ehdr->e_machine, sym, verndx, gnuver, sec, symname);
}

/*
 * Search for and process any symbol tables.
 */
void
symbols(Cache *cache, Word shnum, Ehdr *ehdr, VERSYM_STATE *versym,
    const char *file, uint_t flags)
{
	SYMTBL_STATE state;
	Cache *_cache;
	Word secndx;

	for (secndx = 1; secndx < shnum; secndx++) {
		Word		symcnt;
		Shdr		*shdr;

		_cache = &cache[secndx];
		shdr = _cache->c_shdr;

		if ((shdr->sh_type != SHT_SYMTAB) &&
		    (shdr->sh_type != SHT_DYNSYM) &&
		    (shdr->sh_type != SHT_SUNW_LDYNSYM))
			continue;
		if (!match(MATCH_F_ALL, _cache->c_name, secndx, shdr->sh_type))
			continue;

		if (!init_symtbl_state(&state, cache, shnum, secndx, ehdr,
		    versym, file, flags))
			continue;
		/*
		 * Loop through the symbol tables entries.
		 */
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_SYMTAB), state.secname);
		Elf_syms_table_title(0, ELF_DBG_ELFDUMP);

		for (symcnt = 0; symcnt < state.symn; symcnt++)
			output_symbol(&state, symcnt, shdr->sh_info, symcnt,
			    state.sym + symcnt);
	}
}

/*
 * Search for and process any SHT_SUNW_symsort or SHT_SUNW_tlssort sections.
 * These sections are always associated with the .SUNW_ldynsym./.dynsym pair.
 */
static void
sunw_sort(Cache *cache, Word shnum, Ehdr *ehdr, VERSYM_STATE *versym,
    const char *file, uint_t flags)
{
	SYMTBL_STATE	ldynsym_state,	dynsym_state;
	Cache		*sortcache,	*symcache;
	Shdr		*sortshdr,	*symshdr;
	Word		sortsecndx,	symsecndx;
	Word		ldynsym_cnt;
	Word		*ndx;
	Word		ndxn;
	int		output_cnt = 0;
	Conv_inv_buf_t	inv_buf;

	for (sortsecndx = 1; sortsecndx < shnum; sortsecndx++) {

		sortcache = &cache[sortsecndx];
		sortshdr = sortcache->c_shdr;

		if ((sortshdr->sh_type != SHT_SUNW_symsort) &&
		    (sortshdr->sh_type != SHT_SUNW_tlssort))
			continue;
		if (!match(MATCH_F_ALL, sortcache->c_name, sortsecndx,
		    sortshdr->sh_type))
			continue;

		/*
		 * If the section references a SUNW_ldynsym, then we
		 * expect to see the associated .dynsym immediately
		 * following. If it references a .dynsym, there is no
		 * SUNW_ldynsym. If it is any other type, then we don't
		 * know what to do with it.
		 */
		if ((sortshdr->sh_link == 0) || (sortshdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, sortcache->c_name,
			    EC_WORD(sortshdr->sh_link));
			continue;
		}
		symcache = &cache[sortshdr->sh_link];
		symshdr = symcache->c_shdr;
		symsecndx = sortshdr->sh_link;
		ldynsym_cnt = 0;
		switch (symshdr->sh_type) {
		case SHT_SUNW_LDYNSYM:
			if (!init_symtbl_state(&ldynsym_state, cache, shnum,
			    symsecndx, ehdr, versym, file, flags))
				continue;
			ldynsym_cnt = ldynsym_state.symn;
			/*
			 * We know that the dynsym follows immediately
			 * after the SUNW_ldynsym, and so, should be at
			 * (sortshdr->sh_link + 1). However, elfdump is a
			 * diagnostic tool, so we do the full paranoid
			 * search instead.
			 */
			for (symsecndx = 1; symsecndx < shnum; symsecndx++) {
				symcache = &cache[symsecndx];
				symshdr = symcache->c_shdr;
				if (symshdr->sh_type == SHT_DYNSYM)
					break;
			}
			if (symsecndx >= shnum) {	/* Dynsym not found! */
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_NODYNSYM),
				    file, sortcache->c_name);
				continue;
			}
			/* Fallthrough to process associated dynsym */
			/* FALLTHROUGH */
		case SHT_DYNSYM:
			if (!init_symtbl_state(&dynsym_state, cache, shnum,
			    symsecndx, ehdr, versym, file, flags))
				continue;
			break;
		default:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADNDXSEC),
			    file, sortcache->c_name, conv_sec_type(
			    ehdr->e_machine, symshdr->sh_type, 0, &inv_buf));
			continue;
		}

		/*
		 * Output header
		 */
		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		if (ldynsym_cnt > 0) {
			dbg_print(0, MSG_INTL(MSG_ELF_SCN_SYMSORT2),
			    sortcache->c_name, ldynsym_state.secname,
			    dynsym_state.secname);
			/*
			 * The data for .SUNW_ldynsym and dynsym sections
			 * is supposed to be adjacent with SUNW_ldynsym coming
			 * first. Check, and issue a warning if it isn't so.
			 */
			if (((ldynsym_state.sym + ldynsym_state.symn)
			    != dynsym_state.sym) &&
			    ((flags & FLG_CTL_FAKESHDR) == 0))
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_LDYNNOTADJ), file,
				    ldynsym_state.secname,
				    dynsym_state.secname);
		} else {
			dbg_print(0, MSG_INTL(MSG_ELF_SCN_SYMSORT1),
			    sortcache->c_name, dynsym_state.secname);
		}
		Elf_syms_table_title(0, ELF_DBG_ELFDUMP);

		/* If not first one, insert a line of whitespace */
		if (output_cnt++ > 0)
			dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));

		/*
		 * SUNW_dynsymsort and SUNW_dyntlssort are arrays of
		 * symbol indices. Iterate over the array entries,
		 * dispaying the referenced symbols.
		 */
		ndxn = sortshdr->sh_size / sortshdr->sh_entsize;
		ndx = (Word *)sortcache->c_data->d_buf;
		for (; ndxn-- > 0; ndx++) {
			if (*ndx >= ldynsym_cnt) {
				Word sec_ndx = *ndx - ldynsym_cnt;

				output_symbol(&dynsym_state, sec_ndx, 0,
				    *ndx, dynsym_state.sym + sec_ndx);
			} else {
				output_symbol(&ldynsym_state, *ndx, 0,
				    *ndx, ldynsym_state.sym + *ndx);
			}
		}
	}
}

/*
 * Search for and process any relocation sections.
 */
static void
reloc(Cache *cache, Word shnum, Ehdr *ehdr, const char *file)
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
		Conv_inv_buf_t	inv_buf;

		if (((type = shdr->sh_type) != SHT_RELA) &&
		    (type != SHT_REL))
			continue;
		if (!match(MATCH_F_ALL, relname, cnt, type))
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
		if (_cache->c_data == NULL)
			continue;

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
			Half		mach = ehdr->e_machine;
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
				reltype = ELF_R_TYPE(rela->r_info, mach);
			} else {
				rel = (Rel *)rels;
				symndx = ELF_R_SYM(rel->r_info);
				reltype = ELF_R_TYPE(rel->r_info, mach);
			}

			symname = relsymname(cache, _cache, strsec, symndx,
			    symnum, relndx, syms, section, BUFSIZ, file);

			/*
			 * A zero symbol index is only valid for a few
			 * relocations.
			 */
			if (symndx == 0) {
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
					    conv_reloc_type(mach, reltype,
					    0, &inv_buf));
				}
			}

			Elf_reloc_entry_1(0, ELF_DBG_ELFDUMP,
			    MSG_ORIG(MSG_STR_EMPTY), ehdr->e_machine, type,
			    rels, relname, symname, 0);
		}
	}
}


/*
 * This value controls which test dyn_test() performs.
 */
typedef enum { DYN_TEST_ADDR, DYN_TEST_SIZE, DYN_TEST_ENTSIZE } dyn_test_t;

/*
 * Used by dynamic() to compare the value of a dynamic element against
 * the starting address of the section it references.
 *
 * entry:
 *	test_type - Specify which dyn item is being tested.
 *	sh_type - SHT_* type value for required section.
 *	sec_cache - Cache entry for section, or NULL if the object lacks
 *		a section of this type.
 *	dyn - Dyn entry to be tested
 *	dynsec_cnt - # of dynamic section being examined. The first
 *		dynamic section is 1, the next is 2, and so on...
 *	ehdr - ELF header for file
 *	file - Name of file
 */
static void
dyn_test(dyn_test_t test_type, Word sh_type, Cache *sec_cache, Dyn *dyn,
    Word dynsec_cnt, Ehdr *ehdr, const char *file)
{
	Conv_inv_buf_t	buf1, buf2;

	/*
	 * These tests are based around the implicit assumption that
	 * there is only one dynamic section in an object, and also only
	 * one of the sections it references. We have therefore gathered
	 * all of the necessary information to test this in a single pass
	 * over the section headers, which is very efficient. We are not
	 * aware of any case where more than one dynamic section would
	 * be meaningful in an ELF object, so this is a reasonable solution.
	 *
	 * To test multiple dynamic sections correctly would be more
	 * expensive in code and time. We would have to build a data structure
	 * containing all the dynamic elements. Then, we would use the address
	 * to locate the section it references and ensure the section is of
	 * the right type and that the address in the dynamic element is
	 * to the start of the section. Then, we could check the size and
	 * entsize values against those same sections. This is O(n^2), and
	 * also complicated.
	 *
	 * In the highly unlikely case that there is more than one dynamic
	 * section, we only test the first one, and simply allow the values
	 * of the subsequent one to be displayed unchallenged.
	 */
	if (dynsec_cnt != 1)
		return;

	/*
	 * A DT_ item that references a section address should always find
	 * the section in the file.
	 */
	if (sec_cache == NULL) {
		const char *name;

		/*
		 * Supply section names instead of section types for
		 * things that reference progbits so that the error
		 * message will make more sense.
		 */
		switch (dyn->d_tag) {
		case DT_INIT:
			name = MSG_ORIG(MSG_ELF_INIT);
			break;
		case DT_FINI:
			name = MSG_ORIG(MSG_ELF_FINI);
			break;
		default:
			name = conv_sec_type(ehdr->e_machine, sh_type,
			    0, &buf1);
			break;
		}
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_DYNNOBCKSEC), file,
		    name, conv_dyn_tag(dyn->d_tag, ehdr->e_machine, 0, &buf2));
		return;
	}


	switch (test_type) {
	case DYN_TEST_ADDR:
		/* The section address should match the DT_ item value */
		if (dyn->d_un.d_val != sec_cache->c_shdr->sh_addr)
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_DYNBADADDR), file,
			    conv_dyn_tag(dyn->d_tag, ehdr->e_machine, 0, &buf1),
			    EC_ADDR(dyn->d_un.d_val), sec_cache->c_ndx,
			    sec_cache->c_name,
			    EC_ADDR(sec_cache->c_shdr->sh_addr));
		break;

	case DYN_TEST_SIZE:
		/* The section size should match the DT_ item value */
		if (dyn->d_un.d_val != sec_cache->c_shdr->sh_size)
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_DYNBADSIZE), file,
			    conv_dyn_tag(dyn->d_tag, ehdr->e_machine, 0, &buf1),
			    EC_XWORD(dyn->d_un.d_val),
			    sec_cache->c_ndx, sec_cache->c_name,
			    EC_XWORD(sec_cache->c_shdr->sh_size));
		break;

	case DYN_TEST_ENTSIZE:
		/* The sh_entsize value should match the DT_ item value */
		if (dyn->d_un.d_val != sec_cache->c_shdr->sh_entsize)
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_DYNBADENTSIZE), file,
			    conv_dyn_tag(dyn->d_tag, ehdr->e_machine, 0, &buf1),
			    EC_XWORD(dyn->d_un.d_val),
			    sec_cache->c_ndx, sec_cache->c_name,
			    EC_XWORD(sec_cache->c_shdr->sh_entsize));
		break;
	}
}


/*
 * There are some DT_ entries that have corresponding symbols
 * (e.g. DT_INIT and _init). It is expected that these items will
 * both have the same value if both are present. This routine
 * examines the well known symbol tables for such symbols and
 * issues warnings for any that don't match.
 *
 * entry:
 *	dyn - Dyn entry to be tested
 *	symname - Name of symbol that corresponds to dyn
 *	symtab_cache, dynsym_cache, ldynsym_cache - Symbol tables to check
 *	cache - Cache of all section headers
 *	shnum - # of sections in cache
 *	ehdr - ELF header for file
 *	file - Name of file
 */
static void
dyn_symtest(Dyn *dyn, const char *symname, Cache *symtab_cache,
    Cache *dynsym_cache, Cache *ldynsym_cache, Cache *cache,
    Word shnum, Ehdr *ehdr, const char *file)
{
	Conv_inv_buf_t	buf;
	int		i;
	Sym		*sym;
	Cache		*_cache;

	for (i = 0; i < 3; i++) {
		switch (i) {
		case 0:
			_cache = symtab_cache;
			break;
		case 1:
			_cache = dynsym_cache;
			break;
		case 2:
			_cache = ldynsym_cache;
			break;
		}

		if ((_cache != NULL) &&
		    symlookup(symname, cache, shnum, &sym, _cache, file) &&
		    (sym->st_value != dyn->d_un.d_val))
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_DYNSYMVAL),
			    file, _cache->c_name,
			    conv_dyn_tag(dyn->d_tag, ehdr->e_machine, 0, &buf),
			    symname, EC_ADDR(sym->st_value));
	}
}


/*
 * Search for and process a .dynamic section.
 */
static void
dynamic(Cache *cache, Word shnum, Ehdr *ehdr, const char *file)
{
	struct {
		Cache	*symtab;
		Cache	*dynstr;
		Cache	*dynsym;
		Cache	*hash;
		Cache	*fini;
		Cache	*fini_array;
		Cache	*init;
		Cache	*init_array;
		Cache	*preinit_array;
		Cache	*rel;
		Cache	*rela;
		Cache	*sunw_cap;
		Cache	*sunw_ldynsym;
		Cache	*sunw_move;
		Cache	*sunw_syminfo;
		Cache	*sunw_symsort;
		Cache	*sunw_tlssort;
		Cache	*sunw_verdef;
		Cache	*sunw_verneed;
		Cache	*sunw_versym;
	} sec;
	Word	dynsec_ndx;
	Word	dynsec_num;
	int	dynsec_cnt;
	Word	cnt;

	/*
	 * Make a pass over all the sections, gathering section information
	 * we'll need below.
	 */
	dynsec_num = 0;
	bzero(&sec, sizeof (sec));
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache	*_cache = &cache[cnt];

		switch (_cache->c_shdr->sh_type) {
		case SHT_DYNAMIC:
			if (dynsec_num == 0) {
				dynsec_ndx = cnt;

				/* Does it have a valid string table? */
				(void) stringtbl(cache, 0, cnt, shnum, file,
				    0, 0, &sec.dynstr);
			}
			dynsec_num++;
			break;


		case SHT_PROGBITS:
			/*
			 * We want to detect the .init and .fini sections,
			 * if present. These are SHT_PROGBITS, so all we
			 * have to go on is the section name. Normally comparing
			 * names is a bad idea, but there are some special
			 * names (i.e. .init/.fini/.interp) that are very
			 * difficult to use in any other context, and for
			 * these symbols, we do the heuristic match.
			 */
			if (strcmp(_cache->c_name,
			    MSG_ORIG(MSG_ELF_INIT)) == 0) {
				if (sec.init == NULL)
					sec.init = _cache;
			} else if (strcmp(_cache->c_name,
			    MSG_ORIG(MSG_ELF_FINI)) == 0) {
				if (sec.fini == NULL)
					sec.fini = _cache;
			}
			break;

		case SHT_REL:
			/*
			 * We want the SHT_REL section with the lowest
			 * offset. The linker gathers them together,
			 * and puts the address of the first one
			 * into the DT_REL dynamic element.
			 */
			if ((sec.rel == NULL) ||
			    (_cache->c_shdr->sh_offset <
			    sec.rel->c_shdr->sh_offset))
				sec.rel = _cache;
			break;

		case SHT_RELA:
			/* RELA is handled just like RELA above */
			if ((sec.rela == NULL) ||
			    (_cache->c_shdr->sh_offset <
			    sec.rela->c_shdr->sh_offset))
				sec.rela = _cache;
			break;

		/*
		 * The GRAB macro is used for the simple case in which
		 * we simply grab the first section of the desired type.
		 */
#define	GRAB(_sec_type, _sec_field) \
		case _sec_type: \
			if (sec._sec_field == NULL) \
				sec._sec_field = _cache; \
				break
		GRAB(SHT_SYMTAB,	symtab);
		GRAB(SHT_DYNSYM,	dynsym);
		GRAB(SHT_FINI_ARRAY,	fini_array);
		GRAB(SHT_HASH,		hash);
		GRAB(SHT_INIT_ARRAY,	init_array);
		GRAB(SHT_SUNW_move,	sunw_move);
		GRAB(SHT_PREINIT_ARRAY,	preinit_array);
		GRAB(SHT_SUNW_cap,	sunw_cap);
		GRAB(SHT_SUNW_LDYNSYM,	sunw_ldynsym);
		GRAB(SHT_SUNW_syminfo,	sunw_syminfo);
		GRAB(SHT_SUNW_symsort,	sunw_symsort);
		GRAB(SHT_SUNW_tlssort,	sunw_tlssort);
		GRAB(SHT_SUNW_verdef,	sunw_verdef);
		GRAB(SHT_SUNW_verneed,	sunw_verneed);
		GRAB(SHT_SUNW_versym,	sunw_versym);
#undef GRAB
		}
	}

	/*
	 * If no dynamic section, return immediately. If more than one
	 * dynamic section, then something odd is going on and an error
	 * is in order, but then continue on and display them all.
	 */
	if (dynsec_num == 0)
		return;
	if (dynsec_num > 1)
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MULTDYN),
		    file, EC_WORD(dynsec_num));


	dynsec_cnt = 0;
	for (cnt = dynsec_ndx; (cnt < shnum) && (dynsec_cnt < dynsec_num);
	    cnt++) {
		Dyn	*dyn;
		ulong_t	numdyn;
		int	ndx, end_ndx;
		Cache	*_cache = &cache[cnt], *strsec;
		Shdr	*shdr = _cache->c_shdr;
		int	dumped = 0;

		if (shdr->sh_type != SHT_DYNAMIC)
			continue;
		dynsec_cnt++;

		/*
		 * Verify the associated string table section.
		 */
		if (stringtbl(cache, 0, cnt, shnum, file, 0, 0, &strsec) == 0)
			continue;

		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			continue;
		}
		if (_cache->c_data == NULL)
			continue;

		numdyn = shdr->sh_size / shdr->sh_entsize;
		dyn = (Dyn *)_cache->c_data->d_buf;

		/*
		 * We expect the REL/RELA entries to reference the reloc
		 * section with the lowest address. However, this is
		 * not true for dumped objects. Detect if this object has
		 * been dumped so that we can skip the reloc address test
		 * in that case.
		 */
		for (ndx = 0; ndx < numdyn; dyn++, ndx++) {
			if (dyn->d_tag == DT_FLAGS_1) {
				dumped = (dyn->d_un.d_val & DF_1_CONFALT) != 0;
				break;
			}
		}
		dyn = (Dyn *)_cache->c_data->d_buf;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_DYNAMIC), _cache->c_name);

		Elf_dyn_title(0);

		for (ndx = 0; ndx < numdyn; dyn++, ndx++) {
			union {
				Conv_inv_buf_t		inv;
				Conv_dyn_flag_buf_t	flag;
				Conv_dyn_flag1_buf_t	flag1;
				Conv_dyn_posflag1_buf_t	posflag1;
				Conv_dyn_feature1_buf_t	feature1;
			} c_buf;
			const char	*name = NULL;

			/*
			 * Print the information numerically, and if possible
			 * as a string. If a string is available, name is
			 * set to reference it.
			 *
			 * Also, take this opportunity to sanity check
			 * the values of DT elements. In the code above,
			 * we gathered information on sections that are
			 * referenced by the dynamic section. Here, we
			 * compare the attributes of those sections to
			 * the DT_ items that reference them and report
			 * on inconsistencies.
			 *
			 * Things not currently tested that could be improved
			 * in later revisions include:
			 *	- We don't check PLT or GOT related items
			 *	- We don't handle computing the lengths of
			 *		relocation arrays. To handle this
			 *		requires examining data that spans
			 *		across sections, in a contiguous span
			 *		within a single segment.
			 *	- DT_VERDEFNUM and DT_VERNEEDNUM can't be
			 *		verified without parsing the sections.
			 *	- We don't handle DT_SUNW_SYMSZ, which would
			 *		be the sum of the lengths of .dynsym and
			 *		.SUNW_ldynsym
			 *	- DT_SUNW_STRPAD can't be verified other than
			 *		to check that it's not larger than
			 *		the string table.
			 *	- Some items come in "all or none" clusters
			 *		that give an address, element size,
			 *		and data length in bytes. We don't
			 *		verify that there are no missing items
			 *		in such groups.
			 */
			switch (dyn->d_tag) {
			case DT_NULL:
				/*
				 * Special case: DT_NULLs can come in groups
				 * that we prefer to reduce to a single line.
				 */
				end_ndx = ndx;
				while ((end_ndx < (numdyn - 1)) &&
				    ((dyn + 1)->d_tag == DT_NULL)) {
					dyn++;
					end_ndx++;
				}
				Elf_dyn_null_entry(0, dyn, ndx, end_ndx);
				ndx = end_ndx;
				continue;

			/*
			 * String items all reference the dynstr. The string()
			 * function does the necessary sanity checking.
			 */
			case DT_NEEDED:
			case DT_SONAME:
			case DT_FILTER:
			case DT_AUXILIARY:
			case DT_CONFIG:
			case DT_RPATH:
			case DT_RUNPATH:
			case DT_USED:
			case DT_DEPAUDIT:
			case DT_AUDIT:
			case DT_SUNW_AUXILIARY:
			case DT_SUNW_FILTER:
				name = string(_cache, ndx, strsec,
				    file, dyn->d_un.d_ptr);
				break;

			case DT_FLAGS:
				name = conv_dyn_flag(dyn->d_un.d_val,
				    0, &c_buf.flag);
				break;
			case DT_FLAGS_1:
				name = conv_dyn_flag1(dyn->d_un.d_val, 0,
				    &c_buf.flag1);
				break;
			case DT_POSFLAG_1:
				name = conv_dyn_posflag1(dyn->d_un.d_val, 0,
				    &c_buf.posflag1);
				break;
			case DT_FEATURE_1:
				name = conv_dyn_feature1(dyn->d_un.d_val, 0,
				    &c_buf.feature1);
				break;
			case DT_DEPRECATED_SPARC_REGISTER:
				name = MSG_INTL(MSG_STR_DEPRECATED);
				break;

			case DT_SUNW_LDMACH:
				name = conv_ehdr_mach((Half)dyn->d_un.d_val, 0,
				    &c_buf.inv);
				break;

			/*
			 * Cases below this point are strictly sanity checking,
			 * and do not generate a name string. The TEST_ macros
			 * are used to hide the boilerplate arguments neeeded
			 * by dyn_test().
			 */
#define	TEST_ADDR(_sh_type, _sec_field) \
				dyn_test(DYN_TEST_ADDR, _sh_type, \
				    sec._sec_field, dyn, dynsec_cnt, ehdr, file)
#define	TEST_SIZE(_sh_type, _sec_field) \
				dyn_test(DYN_TEST_SIZE, _sh_type, \
				    sec._sec_field, dyn, dynsec_cnt, ehdr, file)
#define	TEST_ENTSIZE(_sh_type, _sec_field) \
				dyn_test(DYN_TEST_ENTSIZE, _sh_type, \
				    sec._sec_field, dyn, dynsec_cnt, ehdr, file)

			case DT_FINI:
				dyn_symtest(dyn, MSG_ORIG(MSG_SYM_FINI),
				    sec.symtab, sec.dynsym, sec.sunw_ldynsym,
				    cache, shnum, ehdr, file);
				TEST_ADDR(SHT_PROGBITS, fini);
				break;

			case DT_FINI_ARRAY:
				TEST_ADDR(SHT_FINI_ARRAY, fini_array);
				break;

			case DT_FINI_ARRAYSZ:
				TEST_SIZE(SHT_FINI_ARRAY, fini_array);
				break;

			case DT_HASH:
				TEST_ADDR(SHT_HASH, hash);
				break;

			case DT_INIT:
				dyn_symtest(dyn, MSG_ORIG(MSG_SYM_INIT),
				    sec.symtab, sec.dynsym, sec.sunw_ldynsym,
				    cache, shnum, ehdr, file);
				TEST_ADDR(SHT_PROGBITS, init);
				break;

			case DT_INIT_ARRAY:
				TEST_ADDR(SHT_INIT_ARRAY, init_array);
				break;

			case DT_INIT_ARRAYSZ:
				TEST_SIZE(SHT_INIT_ARRAY, init_array);
				break;

			case DT_MOVEENT:
				TEST_ENTSIZE(SHT_SUNW_move, sunw_move);
				break;

			case DT_MOVESZ:
				TEST_SIZE(SHT_SUNW_move, sunw_move);
				break;

			case DT_MOVETAB:
				TEST_ADDR(SHT_SUNW_move, sunw_move);
				break;

			case DT_PREINIT_ARRAY:
				TEST_ADDR(SHT_PREINIT_ARRAY, preinit_array);
				break;

			case DT_PREINIT_ARRAYSZ:
				TEST_SIZE(SHT_PREINIT_ARRAY, preinit_array);
				break;

			case DT_REL:
				if (!dumped)
					TEST_ADDR(SHT_REL, rel);
				break;

			case DT_RELENT:
				TEST_ENTSIZE(SHT_REL, rel);
				break;

			case DT_RELA:
				if (!dumped)
					TEST_ADDR(SHT_RELA, rela);
				break;

			case DT_RELAENT:
				TEST_ENTSIZE(SHT_RELA, rela);
				break;

			case DT_STRTAB:
				TEST_ADDR(SHT_STRTAB, dynstr);
				break;

			case DT_STRSZ:
				TEST_SIZE(SHT_STRTAB, dynstr);
				break;

			case DT_SUNW_CAP:
				TEST_ADDR(SHT_SUNW_cap, sunw_cap);
				break;

			case DT_SUNW_SYMTAB:
				TEST_ADDR(SHT_SUNW_LDYNSYM, sunw_ldynsym);
				break;

			case DT_SYMENT:
				TEST_ENTSIZE(SHT_DYNSYM, dynsym);
				break;

			case DT_SYMINENT:
				TEST_ENTSIZE(SHT_SUNW_syminfo, sunw_syminfo);
				break;

			case DT_SYMINFO:
				TEST_ADDR(SHT_SUNW_syminfo, sunw_syminfo);
				break;

			case DT_SYMINSZ:
				TEST_SIZE(SHT_SUNW_syminfo, sunw_syminfo);
				break;

			case DT_SYMTAB:
				TEST_ADDR(SHT_DYNSYM, dynsym);
				break;

			case DT_SUNW_SORTENT:
				/*
				 * This entry is related to both the symsort and
				 * tlssort sections.
				 */
				{
					int test_tls =
					    (sec.sunw_tlssort != NULL);
					int test_sym =
					    (sec.sunw_symsort != NULL) ||
					    !test_tls;
					if (test_sym)
						TEST_ENTSIZE(SHT_SUNW_symsort,
						    sunw_symsort);
					if (test_tls)
						TEST_ENTSIZE(SHT_SUNW_tlssort,
						    sunw_tlssort);
				}
				break;


			case DT_SUNW_SYMSORT:
				TEST_ADDR(SHT_SUNW_symsort, sunw_symsort);
				break;

			case DT_SUNW_SYMSORTSZ:
				TEST_SIZE(SHT_SUNW_symsort, sunw_symsort);
				break;

			case DT_SUNW_TLSSORT:
				TEST_ADDR(SHT_SUNW_tlssort, sunw_tlssort);
				break;

			case DT_SUNW_TLSSORTSZ:
				TEST_SIZE(SHT_SUNW_tlssort, sunw_tlssort);
				break;

			case DT_VERDEF:
				TEST_ADDR(SHT_SUNW_verdef, sunw_verdef);
				break;

			case DT_VERNEED:
				TEST_ADDR(SHT_SUNW_verneed, sunw_verneed);
				break;

			case DT_VERSYM:
				TEST_ADDR(SHT_SUNW_versym, sunw_versym);
				break;
#undef TEST_ADDR
#undef TEST_SIZE
#undef TEST_ENTSIZE
			}

			if (name == NULL)
				name = MSG_ORIG(MSG_STR_EMPTY);
			Elf_dyn_entry(0, dyn, ndx, name, ehdr->e_machine);
		}
	}
}

/*
 * Search for and process a MOVE section.
 */
static void
move(Cache *cache, Word shnum, const char *file, uint_t flags)
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
		if (!match(MATCH_F_ALL, _cache->c_name, cnt, shdr->sh_type))
			continue;

		/*
		 * Determine the move data and number.
		 */
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			continue;
		}
		if (_cache->c_data == NULL)
			continue;

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
			    symndx, symnum, ndx, syms, section, BUFSIZ, file);
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
				    _cache->c_name, EC_WORD(symndx),
				    demangle(symname, flags));
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
 * Callback function for use with conv_str_to_c_literal() below.
 */
/*ARGSUSED2*/
static void
c_literal_cb(const void *ptr, size_t size, void *uvalue)
{
	(void) fwrite(ptr, size, 1, stdout);
}

/*
 * Traverse a note section analyzing each note information block.
 * The data buffers size is used to validate references before they are made,
 * and is decremented as each element is processed.
 */
void
note_entry(Cache *cache, Word *data, size_t size, Ehdr *ehdr, const char *file)
{
	size_t		bsize = size;
	int		cnt = 0;
	int		is_corenote;
	int		do_swap;
	Conv_inv_buf_t	inv_buf;

	do_swap =  _elf_sys_encoding() != ehdr->e_ident[EI_DATA];

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

		/*
		 * Is this a Solaris core note? Such notes all have
		 * the name "CORE".
		 */
		is_corenote = (ehdr->e_type == ET_CORE) &&
		    (namesz == (MSG_STR_CORE_SIZE + 1)) &&
		    (strncmp(MSG_ORIG(MSG_STR_CORE), (char *)data,
		    MSG_STR_CORE_SIZE + 1) == 0);

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_FMT_NOTEENTNDX), EC_WORD(cnt));
		cnt++;
		dbg_print(0, MSG_ORIG(MSG_NOTE_NAMESZ), EC_WORD(namesz));
		dbg_print(0, MSG_ORIG(MSG_NOTE_DESCSZ), EC_WORD(descsz));

		if (is_corenote)
			dbg_print(0, MSG_ORIG(MSG_NOTE_TYPE_STR),
			    conv_cnote_type(type, 0, &inv_buf));
		else
			dbg_print(0, MSG_ORIG(MSG_NOTE_TYPE), EC_WORD(type));
		if (namesz) {
			char	*name = (char *)data;


			dbg_print(0, MSG_ORIG(MSG_NOTE_NAME));
			/*
			 * The name string can contain embedded 'null'
			 * bytes and/or unprintable characters. Also,
			 * the final NULL is documented in the ELF ABI
			 * as being included in the namesz. So, display
			 * the name using C literal string notation, and
			 * include the terminating NULL in the output.
			 * We don't show surrounding double quotes, as
			 * that implies the termination that we are showing
			 * explicitly.
			 */
			(void) fwrite(MSG_ORIG(MSG_STR_8SP),
			    MSG_STR_8SP_SIZE, 1, stdout);
			conv_str_to_c_literal(name, namesz, c_literal_cb, NULL);
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

		if (descsz) {
			int		hexdump = 1;
			const char	*desc = (const char *)data;

			/*
			 * If this is a core note, let the corenote()
			 * function handle it.
			 */
			if (is_corenote) {
				/* We only issue the bad arch error once */
				static int	badnote_done = 0;
				corenote_ret_t	corenote_ret;

				corenote_ret = corenote(ehdr->e_machine,
				    do_swap, type, desc, descsz);
				switch (corenote_ret) {
				case CORENOTE_R_OK:
					hexdump = 0;
					break;
				case CORENOTE_R_BADDATA:
					(void) fprintf(stderr,
					    MSG_INTL(MSG_NOTE_BADCOREDATA),
					    file);
					break;
				case CORENOTE_R_BADARCH:
					if (badnote_done)
						break;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_NOTE_BADCOREARCH),
					    file,
					    conv_ehdr_mach(ehdr->e_machine,
					    0, &inv_buf));
					break;
				}
			}

			/*
			 * The default thing when we don't understand
			 * the note data is to display it as hex bytes.
			 */
			if (hexdump) {
				dbg_print(0, MSG_ORIG(MSG_NOTE_DESC));
				dump_hex_bytes(desc, descsz, 8, 4, 4);
			}
			desc += descsz + pad;

			/* LINTED */
			data = (Word *)desc;
		}
	}
}

/*
 * Search for and process .note sections.
 *
 * Returns the number of note sections seen.
 */
static Word
note(Cache *cache, Word shnum, Ehdr *ehdr, const char *file)
{
	Word	cnt, note_cnt = 0;

	/*
	 * Otherwise look for any .note sections.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;

		if (shdr->sh_type != SHT_NOTE)
			continue;
		note_cnt++;
		if (!match(MATCH_F_ALL, _cache->c_name, cnt, shdr->sh_type))
			continue;

		/*
		 * As these sections are often hand rolled, make sure they're
		 * properly aligned before proceeding, and issue an error
		 * as necessary.
		 *
		 * Note that we will continue on to display the note even
		 * if it has bad alignment. We can do this safely, because
		 * libelf knows the alignment required for SHT_NOTE, and
		 * takes steps to deliver a properly aligned buffer to us
		 * even if the actual file is misaligned.
		 */
		if (shdr->sh_offset & (sizeof (Word) - 1))
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADALIGN),
			    file, _cache->c_name);

		if (_cache->c_data == NULL)
			continue;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_NOTE), _cache->c_name);
		note_entry(_cache, (Word *)_cache->c_data->d_buf,
		/* LINTED */
		    (Word)_cache->c_data->d_size, ehdr, file);
	}

	return (note_cnt);
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
hash(Cache *cache, Word shnum, const char *file, uint_t flags)
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

		/*
		 * Determine the hash table data and size.
		 */
		if ((hshdr->sh_entsize == 0) || (hshdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, hsecname);
			continue;
		}
		if (_cache->c_data == NULL)
			continue;

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

		if (_cache->c_data == NULL)
			continue;

		if ((syms = (Sym *)_cache->c_data->d_buf) == NULL) {
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
group(Cache *cache, Word shnum, const char *file, uint_t flags)
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
		if (!match(MATCH_F_ALL, _cache->c_name, scnt, shdr->sh_type))
			continue;
		if ((_cache->c_data == NULL) ||
		    ((grpdata = (Word *)_cache->c_data->d_buf) == NULL))
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
got(Cache *cache, Word shnum, Ehdr *ehdr, const char *file)
{
	Cache		*gotcache = NULL, *symtab = NULL;
	Addr		gotbgn, gotend;
	Shdr		*gotshdr;
	Word		cnt, gotents, gotndx;
	size_t		gentsize;
	Got_info	*gottable;
	char		*gotdata;
	Sym		*gotsym;
	Xword		gotsymaddr;
	uint_t		sys_encoding;

	/*
	 * First, find the got.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		if (strncmp(cache[cnt].c_name, MSG_ORIG(MSG_ELF_GOT),
		    MSG_ELF_GOT_SIZE) == 0) {
			gotcache = &cache[cnt];
			break;
		}
	}
	if (gotcache == NULL)
		return;

	/*
	 * A got section within a relocatable object is suspicious.
	 */
	if (ehdr->e_type == ET_REL) {
		(void) fprintf(stderr, MSG_INTL(MSG_GOT_UNEXPECTED), file,
		    gotcache->c_name);
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

	if (gotcache->c_data == NULL)
		return;

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
		if (_cache->c_data == NULL)
			continue;

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
				reltype = ELF_R_TYPE(rela->r_info,
				    ehdr->e_machine);
				offset = rela->r_offset;
			} else {
				rel = (Rel *)rels;
				symndx = ELF_R_SYM(rel->r_info);
				reltype = ELF_R_TYPE(rel->r_info,
				    ehdr->e_machine);
				offset = rel->r_offset;
			}

			/*
			 * Only pay attention to relocations against the GOT.
			 */
			if ((offset < gotbgn) || (offset >= gotend))
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
				    section, BUFSIZ, file);
			gip->g_reltype = reltype;
			gip->g_rel = rels;
		}
	}

	if (symlookup(MSG_ORIG(MSG_SYM_GOT), cache, shnum, &gotsym, symtab,
	    file))
		gotsymaddr = gotsym->st_value;
	else
		gotsymaddr = gotbgn;

	dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(0, MSG_INTL(MSG_ELF_SCN_GOT), gotcache->c_name);
	Elf_got_title(0);

	sys_encoding = _elf_sys_encoding();
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
		    ehdr->e_ident[EI_DATA], sys_encoding,
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

/*
 * This variable is used by regular() to communicate the address of
 * the section header cache to sort_shdr_ndx_arr(). Unfortunately,
 * the qsort() interface does not include a userdata argument by which
 * such arbitrary data can be passed, so we are stuck using global data.
 */
static Cache *sort_shdr_ndx_arr_cache;


/*
 * Used with qsort() to sort the section indices so that they can be
 * used to access the section headers in order of increasing data offset.
 *
 * entry:
 *	sort_shdr_ndx_arr_cache - Contains address of
 *		section header cache.
 *	v1, v2 - Point at elements of sort_shdr_bits array to be compared.
 *
 * exit:
 *	Returns -1 (less than), 0 (equal) or 1 (greater than).
 */
static int
sort_shdr_ndx_arr(const void *v1, const void *v2)
{
	Cache	*cache1 = sort_shdr_ndx_arr_cache + *((size_t *)v1);
	Cache	*cache2 = sort_shdr_ndx_arr_cache + *((size_t *)v2);

	if (cache1->c_shdr->sh_offset < cache2->c_shdr->sh_offset)
		return (-1);

	if (cache1->c_shdr->sh_offset > cache2->c_shdr->sh_offset)
		return (1);

	return (0);
}


static int
shdr_cache(const char *file, Elf *elf, Ehdr *ehdr, size_t shstrndx,
    size_t shnum, Cache **cache_ret, Word flags)
{
	Elf_Scn		*scn;
	Elf_Data	*data;
	size_t		ndx;
	Shdr		*nameshdr;
	char		*names = 0;
	Cache		*cache, *_cache;
	size_t		*shdr_ndx_arr, shdr_ndx_arr_cnt;


	/*
	 * Obtain the .shstrtab data buffer to provide the required section
	 * name strings.
	 */
	if (shstrndx == SHN_UNDEF) {
		/*
		 * It is rare, but legal, for an object to lack a
		 * header string table section.
		 */
		names = NULL;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_NOSHSTRSEC), file);
	} else if ((scn = elf_getscn(elf, shstrndx)) == NULL) {
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
		    EC_WORD(elf_ndxscn(scn)));

	} else if ((names = data->d_buf) == 0)
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_SHSTRNULL), file);

	/*
	 * Allocate a cache to maintain a descriptor for each section.
	 */
	if ((*cache_ret = cache = malloc(shnum * sizeof (Cache))) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    file, strerror(err));
		return (0);
	}

	*cache = cache_init;
	_cache = cache;
	_cache++;

	/*
	 * Allocate an array that will hold the section index for
	 * each section that has data in the ELF file:
	 *
	 *	- Is not a NOBITS section
	 *	- Data has non-zero length
	 *
	 * Note that shnum is an upper bound on the size required. It
	 * is likely that we won't use a few of these array elements.
	 * Allocating a modest amount of extra memory in this case means
	 * that we can avoid an extra loop to count the number of needed
	 * items, and can fill this array immediately in the first loop
	 * below.
	 */
	if ((shdr_ndx_arr = malloc(shnum * sizeof (*shdr_ndx_arr))) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    file, strerror(err));
		return (0);
	}
	shdr_ndx_arr_cnt = 0;

	/*
	 * Traverse the sections of the file.  This gathering of data is
	 * carried out in two passes.  First, the section headers are captured
	 * and the section header names are evaluated.  A verification pass is
	 * then carried out over the section information.  Files have been
	 * known to exhibit overlapping (and hence erroneous) section header
	 * information.
	 *
	 * Finally, the data for each section is obtained.  This processing is
	 * carried out after section verification because should any section
	 * header overlap occur, and a file needs translating (ie. xlate'ing
	 * information from a non-native architecture file), then the process
	 * of translation can corrupt the section header information.  Of
	 * course, if there is any section overlap, the data related to the
	 * sections is going to be compromised.  However, it is the translation
	 * of this data that has caused problems with elfdump()'s ability to
	 * extract the data.
	 */
	for (ndx = 1, scn = NULL; scn = elf_nextscn(elf, scn);
	    ndx++, _cache++) {
		char	scnndxnm[100];

		_cache->c_ndx = ndx;
		_cache->c_scn = scn;

		if ((_cache->c_shdr = elf_getshdr(scn)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN),
			    EC_WORD(elf_ndxscn(scn)));
		}

		/*
		 * If this section has data in the file, include it in
		 * the array of sections to check for address overlap.
		 */
		if ((_cache->c_shdr->sh_size != 0) &&
		    (_cache->c_shdr->sh_type != SHT_NOBITS))
			shdr_ndx_arr[shdr_ndx_arr_cnt++] = ndx;

		/*
		 * If a shstrtab exists, assign the section name.
		 */
		if (names && _cache->c_shdr) {
			if (_cache->c_shdr->sh_name &&
			    /* LINTED */
			    (nameshdr->sh_size > _cache->c_shdr->sh_name)) {
				const char	*symname;
				char		*secname;

				secname = names + _cache->c_shdr->sh_name;

				/*
				 * A SUN naming convention employs a "%" within
				 * a section name to indicate a section/symbol
				 * name.  This originated from the compilers
				 * -xF option, that places functions into their
				 * own sections.  This convention (which has no
				 * formal standard) has also been followed for
				 * COMDAT sections.  To demangle the symbol
				 * name, the name must be separated from the
				 * section name.
				 */
				if (((flags & FLG_CTL_DEMANGLE) == 0) ||
				    ((symname = strchr(secname, '%')) == NULL))
					_cache->c_name = secname;
				else {
					size_t	secsz = ++symname - secname;
					size_t	strsz;

					symname = demangle(symname, flags);
					strsz = secsz + strlen(symname) + 1;

					if ((_cache->c_name =
					    malloc(strsz)) == NULL) {
						int err = errno;
						(void) fprintf(stderr,
						    MSG_INTL(MSG_ERR_MALLOC),
						    file, strerror(err));
						return (0);
					}
					(void) snprintf(_cache->c_name, strsz,
					    MSG_ORIG(MSG_FMT_SECSYM),
					    EC_WORD(secsz), secname, symname);
				}
				continue;
			}

			/*
			 * Generate an error if the section name index is zero
			 * or exceeds the shstrtab data.  Fall through to
			 * fabricate a section name.
			 */
			if ((_cache->c_shdr->sh_name == 0) ||
			    /* LINTED */
			    (nameshdr->sh_size <= _cache->c_shdr->sh_name)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSHNAME), file,
				    EC_WORD(ndx),
				    EC_XWORD(_cache->c_shdr->sh_name));
			}
		}

		/*
		 * If there exists no shstrtab data, or a section header has no
		 * name (an invalid index of 0), then compose a name for the
		 * section.
		 */
		(void) snprintf(scnndxnm, sizeof (scnndxnm),
		    MSG_INTL(MSG_FMT_SCNNDX), ndx);

		if ((_cache->c_name = malloc(strlen(scnndxnm) + 1)) == NULL) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
			    file, strerror(err));
			return (0);
		}
		(void) strcpy(_cache->c_name, scnndxnm);
	}

	/*
	 * Having collected all the sections, validate their address range.
	 * Cases have existed where the section information has been invalid.
	 * This can lead to all sorts of other, hard to diagnose errors, as
	 * each section is processed individually (ie. with elf_getdata()).
	 * Here, we carry out some address comparisons to catch a family of
	 * overlapping memory issues we have observed (likely, there are others
	 * that we have yet to discover).
	 *
	 * Note, should any memory overlap occur, obtaining any additional
	 * data from the file is questionable.  However, it might still be
	 * possible to inspect the ELF header, Programs headers, or individual
	 * sections, so rather than bailing on an error condition, continue
	 * processing to see if any data can be salvaged.
	 */
	if (shdr_ndx_arr_cnt > 1) {
		sort_shdr_ndx_arr_cache = cache;
		qsort(shdr_ndx_arr, shdr_ndx_arr_cnt,
		    sizeof (*shdr_ndx_arr), sort_shdr_ndx_arr);
	}
	for (ndx = 0; ndx < shdr_ndx_arr_cnt; ndx++) {
		Cache	*_cache = cache + shdr_ndx_arr[ndx];
		Shdr	*shdr = _cache->c_shdr;
		Off	bgn1, bgn = shdr->sh_offset;
		Off	end1, end = shdr->sh_offset + shdr->sh_size;
		size_t	ndx1;

		/*
		 * Check the section against all following ones, reporting
		 * any overlaps. Since we've sorted the sections by offset,
		 * we can stop after the first comparison that fails. There
		 * are no overlaps in a properly formed ELF file, in which
		 * case this algorithm runs in O(n) time. This will degenerate
		 * to O(n^2) for a completely broken file. Such a file is
		 * (1) highly unlikely, and (2) unusable, so it is reasonable
		 * for the analysis to take longer.
		 */
		for (ndx1 = ndx + 1; ndx1 < shdr_ndx_arr_cnt; ndx1++) {
			Cache	*_cache1 = cache + shdr_ndx_arr[ndx1];
			Shdr	*shdr1 = _cache1->c_shdr;

			bgn1 = shdr1->sh_offset;
			end1 = shdr1->sh_offset + shdr1->sh_size;

			if (((bgn1 <= bgn) && (end1 > bgn)) ||
			    ((bgn1 < end) && (end1 >= end))) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_SECMEMOVER), file,
				    EC_WORD(elf_ndxscn(_cache->c_scn)),
				    _cache->c_name, EC_OFF(bgn), EC_OFF(end),
				    EC_WORD(elf_ndxscn(_cache1->c_scn)),
				    _cache1->c_name, EC_OFF(bgn1),
				    EC_OFF(end1));
			} else {	/* No overlap, so can stop */
				break;
			}
		}

		/*
		 * In addition to checking for sections overlapping
		 * each other (done above), we should also make sure
		 * the section doesn't overlap the section header array.
		 */
		bgn1 = ehdr->e_shoff;
		end1 = ehdr->e_shoff + (ehdr->e_shentsize * ehdr->e_shnum);

		if (((bgn1 <= bgn) && (end1 > bgn)) ||
		    ((bgn1 < end) && (end1 >= end))) {
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_SHDRMEMOVER), file, EC_OFF(bgn1),
			    EC_OFF(end1),
			    EC_WORD(elf_ndxscn(_cache->c_scn)),
			    _cache->c_name, EC_OFF(bgn), EC_OFF(end));
		}
	}

	/*
	 * Obtain the data for each section.
	 */
	for (ndx = 1; ndx < shnum; ndx++) {
		Cache	*_cache = &cache[ndx];
		Elf_Scn	*scn = _cache->c_scn;

		if ((_cache->c_data = elf_getdata(scn, NULL)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETDATA));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCNDATA),
			    EC_WORD(elf_ndxscn(scn)));
		}

		/*
		 * If a string table, verify that it has NULL first and
		 * final bytes.
		 */
		if ((_cache->c_shdr->sh_type == SHT_STRTAB) &&
		    (_cache->c_data->d_buf != NULL) &&
		    (_cache->c_data->d_size > 0)) {
			const char *s = _cache->c_data->d_buf;

			if ((*s != '\0') ||
			    (*(s + _cache->c_data->d_size - 1) != '\0'))
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALSTR),
				    file, _cache->c_name);
		}
	}

	return (1);
}



int
regular(const char *file, int fd, Elf *elf, uint_t flags,
    const char *wname, int wfd)
{
	Elf_Scn		*scn;
	Ehdr		*ehdr;
	size_t		ndx, shstrndx, shnum, phnum;
	Shdr		*shdr;
	Cache		*cache;
	VERSYM_STATE	versym;
	int		ret = 0;
	int		addr_align;

	if ((ehdr = elf_getehdr(elf)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETEHDR));
		return (ret);
	}

	if (elf_getshnum(elf, &shnum) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHNUM));
		return (ret);
	}

	if (elf_getshstrndx(elf, &shstrndx) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHSTRNDX));
		return (ret);
	}

	if (elf_getphnum(elf, &phnum) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHNUM));
		return (ret);
	}
	/*
	 * If the user requested section headers derived from the
	 * program headers (-P option) and this file doesn't have
	 * any program headers (i.e. ET_REL), then we can't do it.
	 */
	if ((phnum == 0) && (flags & FLG_CTL_FAKESHDR)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_PNEEDSPH), file);
		return (ret);
	}


	if ((scn = elf_getscn(elf, 0)) != NULL) {
		if ((shdr = elf_getshdr(scn)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN), 0);
			return (ret);
		}
	} else
		shdr = 0;

	/*
	 * Print the elf header.
	 */
	if (flags & FLG_SHOW_EHDR)
		Elf_ehdr(0, ehdr, shdr);

	/*
	 * If the section headers or program headers have inadequate
	 * alignment for the class of object, print a warning. libelf
	 * can handle such files, but programs that use them can crash
	 * when they dereference unaligned items.
	 *
	 * Note that the AMD64 ABI, although it is a 64-bit architecture,
	 * allows access to data types smaller than 128-bits to be on
	 * word alignment.
	 */
	if (ehdr->e_machine == EM_AMD64)
		addr_align = sizeof (Word);
	else
		addr_align = sizeof (Addr);

	if (ehdr->e_phoff & (addr_align - 1))
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADPHDRALIGN), file);
	if (ehdr->e_shoff & (addr_align - 1))
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHDRALIGN), file);

	/*
	 * Print the program headers.
	 */
	if ((flags & FLG_SHOW_PHDR) && (phnum != 0)) {
		Phdr	*phdr;

		if ((phdr = elf_getphdr(elf)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
			return (ret);
		}

		for (ndx = 0; ndx < phnum; phdr++, ndx++) {
			if (!match(MATCH_F_PHDR| MATCH_F_NDX | MATCH_F_TYPE,
			    NULL, ndx, phdr->p_type))
				continue;

			dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(0, MSG_INTL(MSG_ELF_PHDR), EC_WORD(ndx));
			Elf_phdr(0, ehdr->e_machine, phdr);
		}
	}

	/*
	 * If we have flag bits set that explicitly require a show or calc
	 * operation, but none of them require the section headers, then
	 * we are done and can return now.
	 */
	if (((flags & (FLG_MASK_SHOW | FLG_MASK_CALC)) != 0) &&
	    ((flags & (FLG_MASK_SHOW_SHDR | FLG_MASK_CALC_SHDR)) == 0))
		return (ret);

	/*
	 * If there are no section headers, then resort to synthesizing
	 * section headers from the program headers. This is normally
	 * only done by explicit request, but in this case there's no
	 * reason not to go ahead, since the alternative is simply to quit.
	 */
	if ((shnum <= 1) && ((flags & FLG_CTL_FAKESHDR) == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_NOSHDR), file);
		flags |= FLG_CTL_FAKESHDR;
	}

	/*
	 * Generate a cache of section headers and related information
	 * for use by the rest of elfdump. If requested (or the file
	 * contains no section headers), we generate a fake set of
	 * headers from the information accessible from the program headers.
	 * Otherwise, we use the real section headers contained in the file.
	 */

	if (flags & FLG_CTL_FAKESHDR) {
		if (fake_shdr_cache(file, fd, elf, ehdr, &cache, &shnum) == 0)
			return (ret);
	} else {
		if (shdr_cache(file, elf, ehdr, shstrndx, shnum,
		    &cache, flags) == 0)
			return (ret);
	}

	/*
	 * Everything from this point on requires section headers.
	 * If we have no section headers, there is no reason to continue.
	 */
	if (shnum <= 1)
		goto done;

	/*
	 * If -w was specified, find and write out the section(s) data.
	 */
	if (wfd) {
		for (ndx = 1; ndx < shnum; ndx++) {
			Cache	*_cache = &cache[ndx];

			if (match(MATCH_F_STRICT | MATCH_F_ALL, _cache->c_name,
			    ndx, _cache->c_shdr->sh_type) &&
			    _cache->c_data && _cache->c_data->d_buf) {
				if (write(wfd, _cache->c_data->d_buf,
				    _cache->c_data->d_size) !=
				    _cache->c_data->d_size) {
					int err = errno;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_WRITE), wname,
					    strerror(err));
					/*
					 * Return an exit status of 1, because
					 * the failure is not related to the
					 * ELF file, but by system resources.
					 */
					ret = 1;
					goto done;
				}
			}
		}
	}

	/*
	 * If we have no flag bits set that explicitly require a show or calc
	 * operation, but match options (-I, -N, -T) were used, then run
	 * through the section headers and see if we can't deduce show flags
	 * from the match options given.
	 *
	 * We don't do this if -w was specified, because (-I, -N, -T) used
	 * with -w in lieu of some other option is supposed to be quiet.
	 */
	if ((wfd == 0) && (flags & FLG_CTL_MATCH) &&
	    ((flags & (FLG_MASK_SHOW | FLG_MASK_CALC)) == 0)) {
		for (ndx = 1; ndx < shnum; ndx++) {
			Cache	*_cache = &cache[ndx];

			if (!match(MATCH_F_STRICT | MATCH_F_ALL, _cache->c_name,
			    ndx, _cache->c_shdr->sh_type))
				continue;

			switch (_cache->c_shdr->sh_type) {
			case SHT_PROGBITS:
				/*
				 * Heuristic time: It is usually bad form
				 * to assume that specific section names
				 * have a given meaning. However, the
				 * ELF ABI does specify a few such names. Try
				 * to match them:
				 */
				if (strcmp(_cache->c_name,
				    MSG_ORIG(MSG_ELF_INTERP)) == 0)
					flags |= FLG_SHOW_INTERP;
				else if (strcmp(_cache->c_name,
				    MSG_ORIG(MSG_ELF_GOT)) == 0)
					flags |= FLG_SHOW_GOT;
				break;

			case SHT_SYMTAB:
			case SHT_DYNSYM:
			case SHT_SUNW_LDYNSYM:
			case SHT_SUNW_versym:
			case SHT_SYMTAB_SHNDX:
				flags |= FLG_SHOW_SYMBOLS;
				break;

			case SHT_RELA:
			case SHT_REL:
				flags |= FLG_SHOW_RELOC;
				break;

			case SHT_HASH:
				flags |= FLG_SHOW_HASH;
				break;

			case SHT_DYNAMIC:
				flags |= FLG_SHOW_DYNAMIC;
				break;

			case SHT_NOTE:
				flags |= FLG_SHOW_NOTE;
				break;

			case SHT_GROUP:
				flags |= FLG_SHOW_GROUP;
				break;

			case SHT_SUNW_symsort:
			case SHT_SUNW_tlssort:
				flags |= FLG_SHOW_SORT;
				break;

			case SHT_SUNW_cap:
				flags |= FLG_SHOW_CAP;
				break;

			case SHT_SUNW_move:
				flags |= FLG_SHOW_MOVE;
				break;

			case SHT_SUNW_syminfo:
				flags |= FLG_SHOW_SYMINFO;
				break;

			case SHT_SUNW_verdef:
			case SHT_SUNW_verneed:
				flags |= FLG_SHOW_VERSIONS;
				break;

			case SHT_AMD64_UNWIND:
				flags |= FLG_SHOW_UNWIND;
				break;
			}
		}
	}


	if (flags & FLG_SHOW_SHDR)
		sections(file, cache, shnum, ehdr);

	if (flags & FLG_SHOW_INTERP)
		interp(file, cache, shnum, phnum, elf);

	versions(cache, shnum, file, flags, &versym);

	if (flags & FLG_SHOW_SYMBOLS)
		symbols(cache, shnum, ehdr, &versym, file, flags);

	if (flags & FLG_SHOW_SORT)
		sunw_sort(cache, shnum, ehdr, &versym, file, flags);

	if (flags & FLG_SHOW_HASH)
		hash(cache, shnum, file, flags);

	if (flags & FLG_SHOW_GOT)
		got(cache, shnum, ehdr, file);

	if (flags & FLG_SHOW_GROUP)
		group(cache, shnum, file, flags);

	if (flags & FLG_SHOW_SYMINFO)
		syminfo(cache, shnum, file);

	if (flags & FLG_SHOW_RELOC)
		reloc(cache, shnum, ehdr, file);

	if (flags & FLG_SHOW_DYNAMIC)
		dynamic(cache, shnum, ehdr, file);

	if (flags & FLG_SHOW_NOTE) {
		Word	note_cnt;
		size_t	note_shnum;
		Cache	*note_cache;

		note_cnt = note(cache, shnum, ehdr, file);

		/*
		 * Solaris core files have section headers, but these
		 * headers do not include SHT_NOTE sections that reference
		 * the core note sections. This means that note() won't
		 * find the core notes. Fake section headers (-P option)
		 * recover these sections, but it is inconvenient to require
		 * users to specify -P in this situation. If the following
		 * are all true:
		 *
		 *	- No note sections were found
		 *	- This is a core file
		 *	- We are not already using fake section headers
		 *
		 * then we will automatically generate fake section headers
		 * and then process them in a second call to note().
		 */
		if ((note_cnt == 0) && (ehdr->e_type == ET_CORE) &&
		    !(flags & FLG_CTL_FAKESHDR) &&
		    (fake_shdr_cache(file, fd, elf, ehdr,
		    &note_cache, &note_shnum) != 0)) {
			(void) note(note_cache, note_shnum, ehdr, file);
			fake_shdr_cache_free(note_cache, note_shnum);
		}
	}

	if (flags & FLG_SHOW_MOVE)
		move(cache, shnum, file, flags);

	if (flags & FLG_CALC_CHECKSUM)
		checksum(elf);

	if (flags & FLG_SHOW_CAP)
		cap(file, cache, shnum, phnum, ehdr, elf);

	if (flags & FLG_SHOW_UNWIND)
		unwind(cache, shnum, phnum, ehdr, file, elf);


	/* Release the memory used to cache section headers */
done:
	if (flags & FLG_CTL_FAKESHDR)
		fake_shdr_cache_free(cache, shnum);
	else
		free(cache);

	return (ret);
}
