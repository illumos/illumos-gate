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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

/*
 * Dump an elf file.
 */
#include	<stddef.h>
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
	uchar_t		osabi;		/* OSABI to use */
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
 * A variable of this type is used to track information related to
 * .eh_frame and .eh_frame_hdr sections across calls to unwind_eh_frame().
 */
typedef struct {
	Word		frame_cnt;	/* # .eh_frame sections seen */
	Word		frame_ndx;	/* Section index of 1st .eh_frame */
	Word		hdr_cnt;	/* # .eh_frame_hdr sections seen */
	Word		hdr_ndx;	/* Section index of 1st .eh_frame_hdr */
	uint64_t	frame_ptr;	/* Value of FramePtr field from first */
					/*	.eh_frame_hdr section */
	uint64_t	frame_base;	/* Data addr of 1st .eh_frame  */
} gnu_eh_state_t;

/*
 * C++ .exception_ranges entries make use of the signed ptrdiff_t
 * type to record self-relative pointer values. We need a type
 * for this that is matched to the ELFCLASS being processed.
 */
#if	defined(_ELF64)
	typedef int64_t PTRDIFF_T;
#else
	typedef int32_t PTRDIFF_T;
#endif

/*
 * The Sun C++ ABI uses this struct to define each .exception_ranges
 * entry. From the ABI:
 *
 * The field ret_addr is a self relative pointer to the start of the address
 * range. The name was chosen because in the current implementation the range
 * typically starts at the return address for a call site.
 *
 * The field length is the difference, in bytes, between the pc of the last
 * instruction covered by the exception range and the first. When only a
 * single call site is represented without optimization, this will equal zero.
 *
 * The field handler_addr is a relative pointer which stores the difference
 * between the start of the exception range and the address of all code to
 * catch exceptions and perform the cleanup for stack unwinding.
 *
 * The field type_block is a relative pointer which stores the difference
 * between the start of the exception range and the address of an array used
 * for storing a list of the types of exceptions which can be caught within
 * the exception range.
 */
typedef struct {
	PTRDIFF_T	ret_addr;
	Xword		length;
	PTRDIFF_T	handler_addr;
	PTRDIFF_T	type_block;
	Xword		reserved;
} exception_range_entry;

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
		if (strs == NULL) {
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
 *
 * entry:
 *	name - Name of symbol to lookup
 *	cache - Cache of all section headers
 *	shnum - # of sections in cache
 *	sym - Address of pointer to receive symbol
 *	target - NULL, or section to which the symbol must be associated.
 *	symtab - Symbol table to search for symbol
 *	file - Name of file
 *
 * exit:
 *	If the symbol is found, *sym is set to reference it, and True is
 *	returned. If target is non-NULL, the symbol must reference the given
 *	section --- otherwise the section is not checked.
 *
 *	If no symbol is found, False is returned.
 */
static int
symlookup(const char *name, Cache *cache, Word shnum, Sym **sym,
    Cache *target, Cache *symtab, const char *file)
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
	*sym = NULL;
	for (cnt = 0; cnt < symn; syms++, cnt++) {
		const char	*symname;

		symname = string(symtab, cnt, &cache[shdr->sh_link], file,
		    syms->st_name);

		if (symname && (strcmp(name, symname) == 0) &&
		    ((target == NULL) || (target->c_ndx == syms->st_shndx))) {
			/*
			 * It is possible, though rare, for a local and
			 * global symbol of the same name to exist, each
			 * contributed by a different input object. If the
			 * symbol just found is local, remember it, but
			 * continue looking.
			 */
			*sym = syms;
			if (ELF_ST_BIND(syms->st_info) != STB_LOCAL)
				break;
		}
	}

	return (*sym != NULL);
}

/*
 * Print section headers.
 */
static void
sections(const char *file, Cache *cache, Word shnum, Ehdr *ehdr, uchar_t osabi)
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
		Elf_shdr(0, osabi, ehdr->e_machine, shdr);
	}
}

/*
 * Obtain a specified Phdr entry.
 */
static Phdr *
getphdr(Word phnum, Word *type_arr, Word type_cnt, const char *file, Elf *elf)
{
	Word	cnt, tcnt;
	Phdr	*phdr;

	if ((phdr = elf_getphdr(elf)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
		return (NULL);
	}

	for (cnt = 0; cnt < phnum; phdr++, cnt++) {
		for (tcnt = 0; tcnt < type_cnt; tcnt++) {
			if (phdr->p_type == type_arr[tcnt])
				return (phdr);
		}
	}
	return (NULL);
}

/*
 * Display the contents of GNU/amd64 .eh_frame and .eh_frame_hdr
 * sections.
 *
 * entry:
 *	cache - Cache of all section headers
 *	shndx - Index of .eh_frame or .eh_frame_hdr section to be displayed
 *	shnum - Total number of sections which exist
 *	uphdr - NULL, or unwind program header associated with
 *		the .eh_frame_hdr section.
 *	ehdr - ELF header for file
 *	eh_state - Data used across calls to this routine. The
 *		caller should zero it before the first call, and
 *		pass it on every call.
 *	osabi - OSABI to use in displaying information
 *	file - Name of file
 *	flags - Command line option flags
 */
static void
unwind_eh_frame(Cache *cache, Word shndx, Word shnum, Phdr *uphdr, Ehdr *ehdr,
    gnu_eh_state_t *eh_state, uchar_t osabi, const char *file, uint_t flags)
{
#if	defined(_ELF64)
#define	MSG_UNW_BINSRTAB2	MSG_UNW_BINSRTAB2_64
#define	MSG_UNW_BINSRTABENT	MSG_UNW_BINSRTABENT_64
#else
#define	MSG_UNW_BINSRTAB2	MSG_UNW_BINSRTAB2_32
#define	MSG_UNW_BINSRTABENT	MSG_UNW_BINSRTABENT_32
#endif

	Cache			*_cache = &cache[shndx];
	Shdr			*shdr = _cache->c_shdr;
	uchar_t			*data = (uchar_t *)(_cache->c_data->d_buf);
	size_t			datasize = _cache->c_data->d_size;
	Conv_dwarf_ehe_buf_t	dwarf_ehe_buf;
	uint64_t		ndx, frame_ptr, fde_cnt, tabndx;
	uint_t			vers, frame_ptr_enc, fde_cnt_enc, table_enc;
	uint64_t		initloc, initloc0 = 0;
	uint64_t		gotaddr = 0;
	int			cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		if (strncmp(cache[cnt].c_name, MSG_ORIG(MSG_ELF_GOT),
		    MSG_ELF_GOT_SIZE) == 0) {
			gotaddr = cache[cnt].c_shdr->sh_addr;
			break;
		}
	}

	if ((data == NULL) || (datasize == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, _cache ->c_name);
		return;
	}

	/*
	 * Is this a .eh_frame_hdr?
	 */
	if ((uphdr && (shdr->sh_addr == uphdr->p_vaddr)) ||
	    (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRMHDR),
	    MSG_SCN_FRMHDR_SIZE) == 0)) {
		/*
		 * There can only be a single .eh_frame_hdr.
		 * Flag duplicates.
		 */
		if (++eh_state->hdr_cnt > 1)
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_MULTEHFRMHDR),
			    file, EC_WORD(shndx), _cache->c_name);

		dbg_print(0, MSG_ORIG(MSG_UNW_FRMHDR));
		ndx = 0;

		vers = data[ndx++];
		frame_ptr_enc = data[ndx++];
		fde_cnt_enc = data[ndx++];
		table_enc = data[ndx++];

		dbg_print(0, MSG_ORIG(MSG_UNW_FRMVERS), vers);

		switch (dwarf_ehe_extract(data, datasize, &ndx,
		    &frame_ptr, frame_ptr_enc, ehdr->e_ident, B_TRUE,
		    shdr->sh_addr, ndx, gotaddr)) {
		case DW_OVERFLOW:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_DWOVRFLW),
			    file, _cache->c_name);
			return;
		case DW_BAD_ENCODING:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_DWBADENC),
			    file, _cache->c_name, frame_ptr_enc);
			return;
		case DW_SUCCESS:
			break;
		}
		if (eh_state->hdr_cnt == 1) {
			eh_state->hdr_ndx = shndx;
			eh_state->frame_ptr = frame_ptr;
		}

		dbg_print(0, MSG_ORIG(MSG_UNW_FRPTRENC),
		    conv_dwarf_ehe(frame_ptr_enc, &dwarf_ehe_buf),
		    EC_XWORD(frame_ptr));

		switch (dwarf_ehe_extract(data, datasize, &ndx, &fde_cnt,
		    fde_cnt_enc, ehdr->e_ident, B_TRUE, shdr->sh_addr, ndx,
		    gotaddr)) {
		case DW_OVERFLOW:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_DWOVRFLW),
			    file, _cache->c_name);
			return;
		case DW_BAD_ENCODING:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_DWBADENC),
			    file, _cache->c_name, fde_cnt_enc);
			return;
		case DW_SUCCESS:
			break;
		}

		dbg_print(0, MSG_ORIG(MSG_UNW_FDCNENC),
		    conv_dwarf_ehe(fde_cnt_enc, &dwarf_ehe_buf),
		    EC_XWORD(fde_cnt));
		dbg_print(0, MSG_ORIG(MSG_UNW_TABENC),
		    conv_dwarf_ehe(table_enc, &dwarf_ehe_buf));
		dbg_print(0, MSG_ORIG(MSG_UNW_BINSRTAB1));
		dbg_print(0, MSG_ORIG(MSG_UNW_BINSRTAB2));

		for (tabndx = 0; tabndx < fde_cnt; tabndx++) {
			uint64_t table;

			switch (dwarf_ehe_extract(data, datasize, &ndx,
			    &initloc, table_enc, ehdr->e_ident, B_TRUE,
			    shdr->sh_addr, ndx, gotaddr)) {
			case DW_OVERFLOW:
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_DWOVRFLW), file,
				    _cache->c_name);
				return;
			case DW_BAD_ENCODING:
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_DWBADENC), file,
				    _cache->c_name, table_enc);
				return;
			case DW_SUCCESS:
				break;
			}
			if ((tabndx != 0) && (initloc0 > initloc))
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSORT), file,
				    _cache->c_name, EC_WORD(tabndx));
			switch (dwarf_ehe_extract(data, datasize, &ndx, &table,
			    table_enc, ehdr->e_ident, B_TRUE, shdr->sh_addr,
			    ndx, gotaddr)) {
			case DW_OVERFLOW:
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_DWOVRFLW), file,
				    _cache->c_name);
				return;
			case DW_BAD_ENCODING:
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_DWBADENC), file,
				    _cache->c_name, table_enc);
				return;
			case DW_SUCCESS:
				break;
			}

			dbg_print(0, MSG_ORIG(MSG_UNW_BINSRTABENT),
			    EC_XWORD(initloc),
			    EC_XWORD(table));
			initloc0 = initloc;
		}
	} else {		/* Display the .eh_frame section */
		eh_state->frame_cnt++;
		if (eh_state->frame_cnt == 1) {
			eh_state->frame_ndx = shndx;
			eh_state->frame_base = shdr->sh_addr;
		} else if ((eh_state->frame_cnt >  1) &&
		    (ehdr->e_type != ET_REL)) {
			Conv_inv_buf_t	inv_buf;

			(void) fprintf(stderr, MSG_INTL(MSG_WARN_MULTEHFRM),
			    file, EC_WORD(shndx), _cache->c_name,
			    conv_ehdr_type(osabi, ehdr->e_type, 0, &inv_buf));
		}
		dump_eh_frame(file, _cache->c_name, data, datasize,
		    shdr->sh_addr, ehdr->e_machine, ehdr->e_ident, gotaddr);
	}

	/*
	 * If we've seen the .eh_frame_hdr and the first .eh_frame section,
	 * compare the header frame_ptr to the address of the actual frame
	 * section to ensure the link-editor got this right.  Note, this
	 * diagnostic is only produced when unwind information is explicitly
	 * asked for, as shared objects built with an older ld(1) may reveal
	 * this inconsistency.  Although an inconsistency, it doesn't seem to
	 * have any adverse effect on existing tools.
	 */
	if (((flags & FLG_MASK_SHOW) != FLG_MASK_SHOW) &&
	    (eh_state->hdr_cnt > 0) && (eh_state->frame_cnt > 0) &&
	    (eh_state->frame_ptr != eh_state->frame_base))
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADEHFRMPTR),
		    file, EC_WORD(eh_state->hdr_ndx),
		    cache[eh_state->hdr_ndx].c_name,
		    EC_XWORD(eh_state->frame_ptr),
		    EC_WORD(eh_state->frame_ndx),
		    cache[eh_state->frame_ndx].c_name,
		    EC_XWORD(eh_state->frame_base));
#undef MSG_UNW_BINSRTAB2
#undef MSG_UNW_BINSRTABENT
}

/*
 * Convert a self relative pointer into an address. A self relative
 * pointer adds the address where the pointer resides to the offset
 * contained in the pointer. The benefit is that the value of the
 * pointer does not require relocation.
 *
 * entry:
 *	base_addr - Address of the pointer.
 *	delta - Offset relative to base_addr giving desired address
 *
 * exit:
 *	The computed address is returned.
 *
 * note:
 *	base_addr is an unsigned value, while ret_addr is signed. This routine
 *	used explicit testing and casting to explicitly control type
 *	conversion, and ensure that we handle the maximum possible range.
 */
static Addr
srelptr(Addr base_addr, PTRDIFF_T delta)
{
	if (delta < 0)
		return (base_addr - (Addr) (-delta));

	return (base_addr + (Addr) delta);
}

/*
 * Byte swap a PTRDIFF_T value.
 */
static PTRDIFF_T
swap_ptrdiff(PTRDIFF_T value)
{
	PTRDIFF_T r;
	uchar_t	*dst = (uchar_t *)&r;
	uchar_t	*src = (uchar_t *)&value;

	UL_ASSIGN_BSWAP_XWORD(dst, src);
	return (r);
}

/*
 * Display exception_range_entry items from the .exception_ranges section
 * of a Sun C++ object.
 */
static void
unwind_exception_ranges(Cache *_cache, const char *file, int do_swap)
{
	/*
	 * Translate a PTRDIFF_T self-relative address field of
	 * an exception_range_entry struct into an address.
	 *
	 * entry:
	 *	exc_addr - Address of base of exception_range_entry struct
	 *	cur_ent - Pointer to data in the struct to be translated
	 *
	 *	_f - Field of struct to be translated
	 */
#define	SRELPTR(_f) \
	srelptr(exc_addr + offsetof(exception_range_entry, _f), cur_ent->_f)

#if	defined(_ELF64)
#define	MSG_EXR_TITLE	MSG_EXR_TITLE_64
#define	MSG_EXR_ENTRY	MSG_EXR_ENTRY_64
#else
#define	MSG_EXR_TITLE	MSG_EXR_TITLE_32
#define	MSG_EXR_ENTRY	MSG_EXR_ENTRY_32
#endif

	exception_range_entry	scratch, *ent, *cur_ent = &scratch;
	char			index[MAXNDXSIZE];
	Word			i, nelts;
	Addr			addr, addr0 = 0, offset = 0;
	Addr			exc_addr = _cache->c_shdr->sh_addr;

	dbg_print(0, MSG_INTL(MSG_EXR_TITLE));
	ent = (exception_range_entry *)(_cache->c_data->d_buf);
	nelts = _cache->c_data->d_size / sizeof (exception_range_entry);

	for (i = 0; i < nelts; i++, ent++) {
		if (do_swap) {
			/*
			 * Copy byte swapped values into the scratch buffer.
			 * The reserved field is not used, so we skip it.
			 */
			scratch.ret_addr = swap_ptrdiff(ent->ret_addr);
			scratch.length = BSWAP_XWORD(ent->length);
			scratch.handler_addr = swap_ptrdiff(ent->handler_addr);
			scratch.type_block = swap_ptrdiff(ent->type_block);
		} else {
			cur_ent = ent;
		}

		/*
		 * The table is required to be sorted by the address
		 * derived from ret_addr, to allow binary searching. Ensure
		 * that addresses grow monotonically.
		 */
		addr = SRELPTR(ret_addr);
		if ((i != 0) && (addr0 > addr))
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSORT),
			    file, _cache->c_name, EC_WORD(i));

		(void) snprintf(index, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INDEX),
		    EC_XWORD(i));
		dbg_print(0, MSG_INTL(MSG_EXR_ENTRY), index, EC_ADDR(offset),
		    EC_ADDR(addr), EC_ADDR(cur_ent->length),
		    EC_ADDR(SRELPTR(handler_addr)),
		    EC_ADDR(SRELPTR(type_block)));

		addr0 = addr;
		exc_addr += sizeof (exception_range_entry);
		offset += sizeof (exception_range_entry);
	}

#undef SRELPTR
#undef MSG_EXR_TITLE
#undef MSG_EXR_ENTRY
}

/*
 * Display information from unwind/exception sections:
 *
 * -	GNU/amd64 .eh_frame and .eh_frame_hdr
 * -	Sun C++ .exception_ranges
 *
 */
static void
unwind(Cache *cache, Word shnum, Word phnum, Ehdr *ehdr, uchar_t osabi,
    const char *file, Elf *elf, uint_t flags)
{
	static Word phdr_types[] = { PT_SUNW_UNWIND, PT_SUNW_EH_FRAME };

	Word			cnt;
	Phdr			*uphdr = NULL;
	gnu_eh_state_t		eh_state;

	/*
	 * Historical background: .eh_frame and .eh_frame_hdr sections
	 * come from the GNU compilers (particularly C++), and are used
	 * under all architectures. Their format is based on DWARF. When
	 * the amd64 ABI was defined, these sections were adopted wholesale
	 * from the existing practice.
	 *
	 * When amd64 support was added to Solaris, support for these
	 * sections was added, using the SHT_AMD64_UNWIND section type
	 * to identify them. At first, we ignored them in objects for
	 * non-amd64 targets, but later broadened our support to include
	 * other architectures in order to better support gcc-generated
	 * objects.
	 *
	 * .exception_ranges implement the same basic concepts, but
	 * were invented at Sun for the Sun C++ compiler.
	 *
	 * We match these sections by name, rather than section type,
	 * because they can come in as either SHT_AMD64_UNWIND, or as
	 * SHT_PROGBITS, and because the type isn't enough to determine
	 * how they should be interpreted.
	 */
	/* Find the program header for .eh_frame_hdr if present */
	if (phnum)
		uphdr = getphdr(phnum, phdr_types,
		    sizeof (phdr_types) / sizeof (*phdr_types), file, elf);

	/*
	 * eh_state is used to retain data used by unwind_eh_frame()
	 * across calls.
	 */
	bzero(&eh_state, sizeof (eh_state));

	for (cnt = 1; cnt < shnum; cnt++) {
		Cache		*_cache = &cache[cnt];
		Shdr		*shdr = _cache->c_shdr;
		int		is_exrange;

		/*
		 * Skip sections of the wrong type. On amd64, they
		 * can be SHT_AMD64_UNWIND. On all platforms, they
		 * can be SHT_PROGBITS (including amd64, if using
		 * the GNU compilers).
		 *
		 * Skip anything other than these two types. The name
		 * test below will thin out the SHT_PROGBITS that don't apply.
		 */
		if ((shdr->sh_type != SHT_PROGBITS) &&
		    (shdr->sh_type != SHT_AMD64_UNWIND))
			continue;

		/*
		 * Only sections with certain well known names are of interest.
		 * These are:
		 *
		 *	.eh_frame - amd64/GNU-compiler unwind sections
		 *	.eh_frame_hdr - Sorted table referencing .eh_frame
		 *	.exception_ranges - Sun C++ unwind sections
		 *
		 * We do a prefix comparison, allowing for naming conventions
		 * like .eh_frame.foo, hence the use of strncmp() rather than
		 * strcmp(). This means that we only really need to test for
		 * .eh_frame, as it's a prefix of .eh_frame_hdr.
		 */
		is_exrange =  strncmp(_cache->c_name,
		    MSG_ORIG(MSG_SCN_EXRANGE), MSG_SCN_EXRANGE_SIZE) == 0;
		if ((strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRM),
		    MSG_SCN_FRM_SIZE) != 0) && !is_exrange)
			continue;

		if (!match(MATCH_F_ALL, _cache->c_name, cnt, shdr->sh_type))
			continue;

		if (_cache->c_data == NULL)
			continue;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_UNWIND), _cache->c_name);

		if (is_exrange)
			unwind_exception_ranges(_cache, file,
			    _elf_sys_encoding() != ehdr->e_ident[EI_DATA]);
		else
			unwind_eh_frame(cache, cnt, shnum, uphdr, ehdr,
			    &eh_state, osabi, file, flags);
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
    Ehdr *ehdr, uchar_t osabi, VERSYM_STATE *versym, const char *file,
    uint_t flags)
{
	Shdr *shdr;

	state->file = file;
	state->ehdr = ehdr;
	state->cache = cache;
	state->osabi = osabi;
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
	if (versym && versym->cache &&
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
	static const int addr_symtype[] = {
		0,			/* STT_NOTYPE */
		1,			/* STT_OBJECT */
		1,			/* STT_FUNC */
		0,			/* STT_SECTION */
		0,			/* STT_FILE */
		1,			/* STT_COMMON */
		0,			/* STT_TLS */
		0,			/* 7 */
		0,			/* 8 */
		0,			/* 9 */
		0,			/* 10 */
		0,			/* 11 */
		0,			/* 12 */
		0,			/* STT_SPARC_REGISTER */
		0,			/* 14 */
		0,			/* 15 */
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
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSYMNDX),
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

	tshdr = NULL;
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
		sec = conv_sym_shndx(state->osabi, state->ehdr->e_machine,
		    sym->st_shndx, CONV_FMT_DECIMAL, &inv_buf);
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
	Elf_syms_table_entry(0, ELF_DBG_ELFDUMP, index, state->osabi,
	    state->ehdr->e_machine, sym, verndx, gnuver, sec, symname);
}

/*
 * Process a SHT_SUNW_cap capabilities section.
 */
static int
cap_section(const char *file, Cache *cache, Word shnum, Cache *ccache,
    uchar_t osabi, Ehdr *ehdr, uint_t flags)
{
	SYMTBL_STATE	state;
	Word		cnum, capnum, nulls, symcaps;
	int		descapndx, objcap, title;
	Cap		*cap = (Cap *)ccache->c_data->d_buf;
	Shdr		*cishdr, *cshdr = ccache->c_shdr;
	Cache		*cicache, *strcache;
	Capinfo		*capinfo = NULL;
	Word		capinfonum;
	const char	*strs = NULL;
	size_t		strs_size;

	if ((cshdr->sh_entsize == 0) || (cshdr->sh_size == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, ccache->c_name);
		return (0);
	}

	/*
	 * If this capabilities section is associated with symbols, then the
	 * sh_link field points to the associated capabilities information
	 * section.  The sh_link field of the capabilities information section
	 * points to the associated symbol table.
	 */
	if (cshdr->sh_link) {
		Cache	*scache;
		Shdr	*sshdr;

		/*
		 * Validate that the sh_link field points to a capabilities
		 * information section.
		 */
		if (cshdr->sh_link >= shnum) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, ccache->c_name, EC_WORD(cshdr->sh_link));
			return (0);
		}

		cicache = &cache[cshdr->sh_link];
		cishdr = cicache->c_shdr;

		if (cishdr->sh_type != SHT_SUNW_capinfo) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_INVCAP),
			    file, ccache->c_name, EC_WORD(cshdr->sh_link));
			return (0);
		}

		capinfo = cicache->c_data->d_buf;
		capinfonum = (Word)(cishdr->sh_size / cishdr->sh_entsize);

		/*
		 * Validate that the sh_link field of the capabilities
		 * information section points to a valid symbol table.
		 */
		if ((cishdr->sh_link == 0) || (cishdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, cicache->c_name, EC_WORD(cishdr->sh_link));
			return (0);
		}
		scache = &cache[cishdr->sh_link];
		sshdr = scache->c_shdr;

		if ((sshdr->sh_type != SHT_SYMTAB) &&
		    (sshdr->sh_type != SHT_DYNSYM)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_INVCAPINFO1),
			    file, cicache->c_name, EC_WORD(cishdr->sh_link));
			return (0);
		}

		if (!init_symtbl_state(&state, cache, shnum,
		    cishdr->sh_link, ehdr, osabi, NULL, file, flags))
			return (0);
	}

	/*
	 * If this capabilities section contains capability string entries,
	 * then determine the associated string table.  Capabilities entries
	 * that define names require that the capability section indicate
	 * which string table to use via sh_info.
	 */
	if (cshdr->sh_info) {
		Shdr	*strshdr;

		/*
		 * Validate that the sh_info field points to a string table.
		 */
		if (cshdr->sh_info >= shnum) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, ccache->c_name, EC_WORD(cshdr->sh_info));
			return (0);
		}

		strcache = &cache[cshdr->sh_info];
		strshdr = strcache->c_shdr;

		if (strshdr->sh_type != SHT_STRTAB) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_INVCAP),
			    file, ccache->c_name, EC_WORD(cshdr->sh_info));
			return (0);
		}
		strs = (const char *)strcache->c_data->d_buf;
		strs_size = strcache->c_data->d_size;
	}

	dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(0, MSG_INTL(MSG_ELF_SCN_CAP), ccache->c_name);

	capnum = (Word)(cshdr->sh_size / cshdr->sh_entsize);

	nulls = symcaps = 0;
	objcap = title = 1;
	descapndx = -1;

	/*
	 * Traverse the capabilities section printing each capability group.
	 * The first capabilities group defines any object capabilities.  Any
	 * following groups define symbol capabilities.  In the case where no
	 * object capabilities exist, but symbol capabilities do, a single
	 * CA_SUNW_NULL terminator for the object capabilities exists.
	 */
	for (cnum = 0; cnum < capnum; cap++, cnum++) {
		if (cap->c_tag == CA_SUNW_NULL) {
			/*
			 * A CA_SUNW_NULL tag terminates a capabilities group.
			 * If the first capabilities tag is CA_SUNW_NULL, then
			 * no object capabilities exist.
			 */
			if ((nulls++ == 0) && (cnum == 0))
				objcap = 0;
			title = 1;
		} else {
			if (title) {
				if (nulls == 0) {
					/*
					 * If this capabilities group represents
					 * the object capabilities (i.e., no
					 * CA_SUNW_NULL tag has been processed
					 * yet), then display an object
					 * capabilities title.
					 */
					dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
					dbg_print(0,
					    MSG_INTL(MSG_OBJ_CAP_TITLE));
				} else {
					/*
					 * If this is a symbols capabilities
					 * group (i.e., a CA_SUNW_NULL tag has
					 * already be found that terminates
					 * the object capabilities group), then
					 * display a symbol capabilities title,
					 * and retain this capabilities index
					 * for later processing.
					 */
					dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
					dbg_print(0,
					    MSG_INTL(MSG_SYM_CAP_TITLE));
					descapndx = cnum;
				}
				Elf_cap_title(0);
				title = 0;
			}

			/*
			 * Print the capabilities data.
			 *
			 * Note that CA_SUNW_PLAT, CA_SUNW_MACH and CA_SUNW_ID
			 * entries require a string table, which should have
			 * already been established.
			 */
			if ((strs == NULL) && ((cap->c_tag == CA_SUNW_PLAT) ||
			    (cap->c_tag == CA_SUNW_MACH) ||
			    (cap->c_tag == CA_SUNW_ID))) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_WARN_INVCAP4), file,
				    EC_WORD(elf_ndxscn(ccache->c_scn)),
				    ccache->c_name, EC_WORD(cshdr->sh_info));
			}
			Elf_cap_entry(0, cap, cnum, strs, strs_size,
			    ehdr->e_machine);
		}

		/*
		 * If this CA_SUNW_NULL tag terminates a symbol capabilities
		 * group, determine the associated symbols.
		 */
		if ((cap->c_tag == CA_SUNW_NULL) && (nulls > 1) &&
		    (descapndx != -1)) {
			Capinfo	*cip;
			Word	inum;

			symcaps++;

			/*
			 * Make sure we've discovered a SHT_SUNW_capinfo table.
			 */
			if ((cip = capinfo) == NULL) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_INVCAP), file,
				    ccache->c_name, EC_WORD(cshdr->sh_link));
				return (0);
			}

			/*
			 * Determine what symbols reference this capabilities
			 * group.
			 */
			dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(0, MSG_INTL(MSG_CAPINFO_ENTRIES));
			Elf_syms_table_title(0, ELF_DBG_ELFDUMP);

			for (inum = 1, cip++; inum < capinfonum;
			    inum++, cip++) {
				Word	gndx = (Word)ELF_C_GROUP(*cip);

				if (gndx && (gndx == descapndx)) {
					output_symbol(&state, inum, 0,
					    inum, state.sym + inum);
				}
			}
			descapndx = -1;
			continue;
		}

		/*
		 * An SF1_SUNW_ADDR32 software capability tag in a 32-bit
		 * object is suspicious as it has no effect.
		 */
		if ((cap->c_tag == CA_SUNW_SF_1) &&
		    (ehdr->e_ident[EI_CLASS] == ELFCLASS32) &&
		    (cap->c_un.c_val & SF1_SUNW_ADDR32)) {
			(void) fprintf(stderr, MSG_INTL(MSG_WARN_INADDR32SF1),
			    file, ccache->c_name);
		}
	}

	/*
	 * If this is a dynamic object, with symbol capabilities, then a
	 * .SUNW_capchain section should exist.  This section contains a chain
	 * of symbol indexes for each capabilities family.  This is the list
	 * that is searched by ld.so.1 to determine the best capabilities
	 * candidate.
	 *
	 * Note, more than one capabilities lead symbol can point to the same
	 * family chain.  For example, a weak/global pair of symbols can both
	 * represent the same family of capabilities symbols.  Therefore, to
	 * display all possible families we traverse the capabilities
	 * information section looking for CAPINFO_SUNW_GLOB lead symbols.
	 * From these we determine the associated capabilities chain to inspect.
	 */
	if (symcaps &&
	    ((ehdr->e_type == ET_EXEC) || (ehdr->e_type == ET_DYN))) {
		Capinfo		*cip;
		Capchain	*chain;
		Cache   	*chcache;
		Shdr		*chshdr;
		Word		chainnum, inum;

		/*
		 * Validate that the sh_info field of the capabilities
		 * information section points to a capabilities chain section.
		 */
		if (cishdr->sh_info >= shnum) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, cicache->c_name, EC_WORD(cishdr->sh_info));
			return (0);
		}

		chcache = &cache[cishdr->sh_info];
		chshdr = chcache->c_shdr;

		if (chshdr->sh_type != SHT_SUNW_capchain) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_INVCAPINFO2),
			    file, cicache->c_name, EC_WORD(cishdr->sh_info));
			return (0);
		}

		chainnum = (Word)(chshdr->sh_size / chshdr->sh_entsize);
		chain = (Capchain *)chcache->c_data->d_buf;

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_ELF_SCN_CAPCHAIN), chcache->c_name);

		/*
		 * Traverse the capabilities information section looking for
		 * CAPINFO_SUNW_GLOB lead capabilities symbols.
		 */
		cip = capinfo;
		for (inum = 1, cip++; inum < capinfonum; inum++, cip++) {
			const char	*name;
			Sym		*sym;
			Word		sndx, cndx;
			Word		gndx = (Word)ELF_C_GROUP(*cip);

			if ((gndx == 0) || (gndx != CAPINFO_SUNW_GLOB))
				continue;

			/*
			 * Determine the symbol that is associated with this
			 * capability information entry, and use this to
			 * identify this capability family.
			 */
			sym = (Sym *)(state.sym + inum);
			name = string(cicache, inum, strcache, file,
			    sym->st_name);

			dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(0, MSG_INTL(MSG_CAPCHAIN_TITLE), name);
			dbg_print(0, MSG_INTL(MSG_CAPCHAIN_ENTRY));

			cndx = (Word)ELF_C_SYM(*cip);

			/*
			 * Traverse this families chain and identify each
			 * family member.
			 */
			for (;;) {
				char	_chain[MAXNDXSIZE], _symndx[MAXNDXSIZE];

				if (cndx >= chainnum) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_INVCAPINFO3), file,
					    cicache->c_name, EC_WORD(inum),
					    EC_WORD(cndx));
					break;
				}
				if ((sndx = chain[cndx]) == 0)
					break;

				/*
				 * Determine this entries symbol reference.
				 */
				if (sndx > state.symn) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_CHBADSYMNDX), file,
					    EC_WORD(sndx), chcache->c_name,
					    EC_WORD(cndx));
					name = MSG_INTL(MSG_STR_UNKNOWN);
				} else {
					sym = (Sym *)(state.sym + sndx);
					name = string(chcache, sndx,
					    strcache, file, sym->st_name);
				}

				/*
				 * Display the family member.
				 */
				(void) snprintf(_chain, MAXNDXSIZE,
				    MSG_ORIG(MSG_FMT_INTEGER), cndx);
				(void) snprintf(_symndx, MAXNDXSIZE,
				    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(sndx));
				dbg_print(0, MSG_ORIG(MSG_FMT_CHAIN_INFO),
				    _chain, _symndx, demangle(name, flags));

				cndx++;
			}
		}
	}
	return (objcap);
}

/*
 * Print the capabilities.
 *
 * A .SUNW_cap section can contain one or more, CA_SUNW_NULL terminated,
 * capabilities groups.  The first group defines the object capabilities.
 * This group defines the minimum capability requirements of the entire
 * object file.  If this is a dynamic object, this group should be associated
 * with a PT_SUNWCAP program header.
 *
 * Additional capabilities groups define the association of individual symbols
 * to specific capabilities.
 */
static void
cap(const char *file, Cache *cache, Word shnum, Word phnum, Ehdr *ehdr,
    uchar_t osabi, Elf *elf, uint_t flags)
{
	Word		cnt;
	Shdr		*cshdr = NULL;
	Cache		*ccache;
	Off		cphdr_off = 0;
	Xword		cphdr_sz;

	/*
	 * Determine if a global capabilities header exists.
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
	 * Determine if a capabilities section exists.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache	*_cache = &cache[cnt];
		Shdr	*shdr = _cache->c_shdr;

		/*
		 * Process any capabilities information.
		 */
		if (shdr->sh_type == SHT_SUNW_cap) {
			if (cap_section(file, cache, shnum, _cache, osabi,
			    ehdr, flags)) {
				/*
				 * If this section defined an object capability
				 * group, retain the section information for
				 * program header validation.
				 */
				ccache = _cache;
				cshdr = shdr;
			}
			continue;
		}
	}

	if ((cshdr == NULL) && (cphdr_off == 0))
		return;

	if (cphdr_off && (cshdr == NULL))
		(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVCAP1), file);

	/*
	 * If this object is an executable or shared object, and it provided
	 * an object capabilities group, then the group should have an
	 * accompanying PT_SUNWCAP program header.
	 */
	if (cshdr && ((ehdr->e_type == ET_EXEC) || (ehdr->e_type == ET_DYN))) {
		if (cphdr_off == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVCAP2),
			    file, EC_WORD(elf_ndxscn(ccache->c_scn)),
			    ccache->c_name);
		} else if ((cphdr_off != cshdr->sh_offset) ||
		    (cphdr_sz != cshdr->sh_size)) {
			(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVCAP3),
			    file, EC_WORD(elf_ndxscn(ccache->c_scn)),
			    ccache->c_name);
		}
	}
}

/*
 * Print the interpretor.
 */
static void
interp(const char *file, Cache *cache, Word shnum, Word phnum, Elf *elf)
{
	static Word phdr_types[] = { PT_INTERP };


	Word	cnt;
	Shdr	*ishdr = NULL;
	Cache	*icache;
	Off	iphdr_off = 0;
	Xword	iphdr_fsz;

	/*
	 * Determine if an interp header exists.
	 */
	if (phnum) {
		Phdr	*phdr;

		phdr = getphdr(phnum, phdr_types,
		    sizeof (phdr_types) / sizeof (*phdr_types), file, elf);
		if (phdr != NULL) {
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
syminfo(Cache *cache, Word shnum, Ehdr *ehdr, uchar_t osabi, const char *file)
{
	Shdr		*infoshdr;
	Syminfo		*info;
	Sym		*syms;
	Dyn		*dyns;
	Word		infonum, cnt, ndx, symnum, dynnum;
	Cache		*infocache = NULL, *dyncache = NULL, *symsec, *strsec;
	Boolean		*dynerr;

	for (cnt = 1; cnt < shnum; cnt++) {
		if (cache[cnt].c_shdr->sh_type == SHT_SUNW_syminfo) {
			infocache = &cache[cnt];
			break;
		}
	}
	if (infocache == NULL)
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
	 * If there is no associated dynamic section, determine if one
	 * is needed, and if so issue a warning. If there is an
	 * associated dynamic section, validate it and get the data buffer
	 * for it.
	 */
	dyns = NULL;
	dynnum = 0;
	if (infoshdr->sh_info == 0) {
		Syminfo	*_info = info + 1;

		for (ndx = 1; ndx < infonum; ndx++, _info++) {
			if ((_info->si_flags == 0) && (_info->si_boundto == 0))
				continue;

			if (_info->si_boundto < SYMINFO_BT_LOWRESERVE)
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSHINFO), file,
				    infocache->c_name,
				    EC_WORD(infoshdr->sh_info));
		}
	} else if ((infoshdr->sh_info >= shnum) ||
	    (cache[infoshdr->sh_info].c_shdr->sh_type != SHT_DYNAMIC)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHINFO),
		    file, infocache->c_name, EC_WORD(infoshdr->sh_info));
	} else {
		dyncache = &cache[infoshdr->sh_info];
		if ((dyncache->c_data == NULL) ||
		    ((dyns = dyncache->c_data->d_buf) == NULL)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, dyncache->c_name);
		}
		if (dyns != NULL) {
			dynnum = dyncache->c_shdr->sh_size /
			    dyncache->c_shdr->sh_entsize;

			/*
			 * We validate the type of dynamic elements referenced
			 * from the syminfo. This array is used report any
			 * bad dynamic entries.
			 */
			if ((dynerr = calloc(dynnum, sizeof (*dynerr))) ==
			    NULL) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
				    file, strerror(err));
				return;
			}
		}
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
		const char	*needed, *name;
		Word		expect_dt;
		Word		boundto = info->si_boundto;

		if ((info->si_flags == 0) && (boundto == 0))
			continue;

		sym = &syms[ndx];
		name = string(infocache, ndx, strsec, file, sym->st_name);

		/* Is si_boundto set to one of the reserved values? */
		if (boundto >= SYMINFO_BT_LOWRESERVE) {
			Elf_syminfo_entry(0, ndx, info, name, NULL);
			continue;
		}

		/*
		 * si_boundto is referencing a dynamic section. If we don't
		 * have one, an error was already issued above, so it suffices
		 * to display an empty string. If we are out of bounds, then
		 * report that and then display an empty string.
		 */
		if ((dyns == NULL) || (boundto >= dynnum)) {
			if (dyns != NULL)
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSIDYNNDX), file,
				    infocache->c_ndx, infocache->c_name,
				    EC_WORD(ndx), EC_WORD(dynnum - 1),
				    EC_WORD(boundto));
			Elf_syminfo_entry(0, ndx, info, name,
			    MSG_ORIG(MSG_STR_EMPTY));
			continue;
		}

		/*
		 * The si_boundto reference expects a specific dynamic element
		 * type at the given index. The dynamic element is always a
		 * string that gives an object name. The specific type depends
		 * on the si_flags present. Ensure that we've got the right
		 * type.
		 */
		if (info->si_flags & SYMINFO_FLG_FILTER)
			expect_dt = DT_SUNW_FILTER;
		else if (info->si_flags & SYMINFO_FLG_AUXILIARY)
			expect_dt = DT_SUNW_AUXILIARY;
		else if (info->si_flags & (SYMINFO_FLG_DIRECT |
		    SYMINFO_FLG_LAZYLOAD | SYMINFO_FLG_DIRECTBIND))
			expect_dt = DT_NEEDED;
		else
			expect_dt = DT_NULL;   /* means we ignore the type */

		if ((dyns[boundto].d_tag != expect_dt) &&
		    (expect_dt != DT_NULL)) {
			Conv_inv_buf_t	buf1, buf2;

			/* Only complain about each dynamic element once */
			if (!dynerr[boundto]) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSIDYNTAG),
				    file, infocache->c_ndx, infocache->c_name,
				    EC_WORD(ndx), dyncache->c_ndx,
				    dyncache->c_name, EC_WORD(boundto),
				    conv_dyn_tag(expect_dt, osabi,
				    ehdr->e_machine, CONV_FMT_ALT_CF, &buf1),
				    conv_dyn_tag(dyns[boundto].d_tag, osabi,
				    ehdr->e_machine, CONV_FMT_ALT_CF, &buf2));
				dynerr[boundto] = TRUE;
			}
		}

		/*
		 * Whether or not the DT item we're pointing at is
		 * of the right type, if it's a type we recognize as
		 * providing a string, go ahead and show it. Otherwise
		 * an empty string.
		 */
		switch (dyns[boundto].d_tag) {
		case DT_NEEDED:
		case DT_SONAME:
		case DT_RPATH:
		case DT_RUNPATH:
		case DT_CONFIG:
		case DT_DEPAUDIT:
		case DT_USED:
		case DT_AUDIT:
		case DT_SUNW_AUXILIARY:
		case DT_SUNW_FILTER:
		case DT_FILTER:
		case DT_AUXILIARY:
			needed = string(infocache, boundto,
			    strsec, file, dyns[boundto].d_un.d_val);
			break;
		default:
			needed = MSG_ORIG(MSG_STR_EMPTY);
		}
		Elf_syminfo_entry(0, ndx, info, name, needed);
	}
	if (dyns != NULL)
		free(dynerr);
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
 * Search for and process any symbol tables.
 */
void
symbols(Cache *cache, Word shnum, Ehdr *ehdr, uchar_t osabi,
    VERSYM_STATE *versym, const char *file, uint_t flags)
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
		    ((shdr->sh_type != SHT_SUNW_LDYNSYM) ||
		    (osabi != ELFOSABI_SOLARIS)))
			continue;
		if (!match(MATCH_F_ALL, _cache->c_name, secndx, shdr->sh_type))
			continue;

		if (!init_symtbl_state(&state, cache, shnum, secndx, ehdr,
		    osabi, versym, file, flags))
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
sunw_sort(Cache *cache, Word shnum, Ehdr *ehdr, uchar_t osabi,
    VERSYM_STATE *versym, const char *file, uint_t flags)
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
			    symsecndx, ehdr, osabi, versym, file, flags))
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
			    symsecndx, ehdr, osabi, versym, file, flags))
				continue;
			break;
		default:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADNDXSEC),
			    file, sortcache->c_name,
			    conv_sec_type(osabi, ehdr->e_machine,
			    symshdr->sh_type, 0, &inv_buf));
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

		/* If not first one, insert a line of white space */
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
    Word dynsec_cnt, Ehdr *ehdr, uchar_t osabi, const char *file)
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
			name = conv_sec_type(osabi, ehdr->e_machine,
			    sh_type, 0, &buf1);
			break;
		}
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_DYNNOBCKSEC), file,
		    name, conv_dyn_tag(dyn->d_tag, osabi, ehdr->e_machine,
		    CONV_FMT_ALT_CF, &buf2));
		return;
	}


	switch (test_type) {
	case DYN_TEST_ADDR:
		/* The section address should match the DT_ item value */
		if (dyn->d_un.d_val != sec_cache->c_shdr->sh_addr)
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_DYNBADADDR), file,
			    conv_dyn_tag(dyn->d_tag, osabi, ehdr->e_machine,
			    CONV_FMT_ALT_CF, &buf1), EC_ADDR(dyn->d_un.d_val),
			    sec_cache->c_ndx, sec_cache->c_name,
			    EC_ADDR(sec_cache->c_shdr->sh_addr));
		break;

	case DYN_TEST_SIZE:
		/* The section size should match the DT_ item value */
		if (dyn->d_un.d_val != sec_cache->c_shdr->sh_size)
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_DYNBADSIZE), file,
			    conv_dyn_tag(dyn->d_tag, osabi, ehdr->e_machine,
			    CONV_FMT_ALT_CF, &buf1), EC_XWORD(dyn->d_un.d_val),
			    sec_cache->c_ndx, sec_cache->c_name,
			    EC_XWORD(sec_cache->c_shdr->sh_size));
		break;

	case DYN_TEST_ENTSIZE:
		/* The sh_entsize value should match the DT_ item value */
		if (dyn->d_un.d_val != sec_cache->c_shdr->sh_entsize)
			(void) fprintf(stderr,
			    MSG_INTL(MSG_ERR_DYNBADENTSIZE), file,
			    conv_dyn_tag(dyn->d_tag, osabi, ehdr->e_machine,
			    CONV_FMT_ALT_CF, &buf1), EC_XWORD(dyn->d_un.d_val),
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
 *	target_cache - Section the symname section is expected to be
 *		associated with.
 *	cache - Cache of all section headers
 *	shnum - # of sections in cache
 *	ehdr - ELF header for file
 *	osabi - OSABI to apply when interpreting object
 *	file - Name of file
 */
static void
dyn_symtest(Dyn *dyn, const char *symname, Cache *symtab_cache,
    Cache *dynsym_cache, Cache *ldynsym_cache, Cache *target_cache,
    Cache *cache, Word shnum, Ehdr *ehdr, uchar_t osabi, const char *file)
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
		    symlookup(symname, cache, shnum, &sym, target_cache,
		    _cache, file) && (sym->st_value != dyn->d_un.d_val))
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_DYNSYMVAL),
			    file, _cache->c_name, conv_dyn_tag(dyn->d_tag,
			    osabi, ehdr->e_machine, CONV_FMT_ALT_CF, &buf),
			    symname, EC_ADDR(sym->st_value));
	}
}

/*
 * Search for and process a .dynamic section.
 */
static void
dynamic(Cache *cache, Word shnum, Ehdr *ehdr, uchar_t osabi, const char *file)
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
		Cache	*sunw_capinfo;
		Cache	*sunw_capchain;
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
	int	osabi_solaris = osabi == ELFOSABI_SOLARIS;

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
		GRAB(SHT_SUNW_capinfo,	sunw_capinfo);
		GRAB(SHT_SUNW_capchain,	sunw_capchain);
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
				name = string(_cache, ndx, strsec,
				    file, dyn->d_un.d_ptr);
				break;

			case DT_SUNW_AUXILIARY:
			case DT_SUNW_FILTER:
				if (osabi_solaris)
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
				if (!osabi_solaris)
					break;
				name = conv_ehdr_mach((Half)dyn->d_un.d_val,
				    0, &c_buf.inv);
				break;

			/*
			 * Cases below this point are strictly sanity checking,
			 * and do not generate a name string. The TEST_ macros
			 * are used to hide the boiler plate arguments neeeded
			 * by dyn_test().
			 */
#define	TEST_ADDR(_sh_type, _sec_field) \
				dyn_test(DYN_TEST_ADDR, _sh_type, \
				    sec._sec_field, dyn, dynsec_cnt, ehdr, \
				    osabi, file)
#define	TEST_SIZE(_sh_type, _sec_field) \
				dyn_test(DYN_TEST_SIZE, _sh_type, \
				    sec._sec_field, dyn, dynsec_cnt, ehdr, \
				    osabi, file)
#define	TEST_ENTSIZE(_sh_type, _sec_field) \
				dyn_test(DYN_TEST_ENTSIZE, _sh_type, \
				    sec._sec_field, dyn, dynsec_cnt, ehdr, \
				    osabi, file)

			case DT_FINI:
				dyn_symtest(dyn, MSG_ORIG(MSG_SYM_FINI),
				    sec.symtab, sec.dynsym, sec.sunw_ldynsym,
				    sec.fini, cache, shnum, ehdr, osabi, file);
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
				    sec.init, cache, shnum, ehdr, osabi, file);
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
				if (osabi_solaris)
					TEST_ADDR(SHT_SUNW_cap, sunw_cap);
				break;

			case DT_SUNW_CAPINFO:
				if (osabi_solaris)
					TEST_ADDR(SHT_SUNW_capinfo,
					    sunw_capinfo);
				break;

			case DT_SUNW_CAPCHAIN:
				if (osabi_solaris)
					TEST_ADDR(SHT_SUNW_capchain,
					    sunw_capchain);
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
				if (osabi_solaris) {
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
				if (osabi_solaris)
					TEST_ADDR(SHT_SUNW_symsort,
					    sunw_symsort);
				break;

			case DT_SUNW_SYMSORTSZ:
				if (osabi_solaris)
					TEST_SIZE(SHT_SUNW_symsort,
					    sunw_symsort);
				break;

			case DT_SUNW_TLSSORT:
				if (osabi_solaris)
					TEST_ADDR(SHT_SUNW_tlssort,
					    sunw_tlssort);
				break;

			case DT_SUNW_TLSSORTSZ:
				if (osabi_solaris)
					TEST_SIZE(SHT_SUNW_tlssort,
					    sunw_tlssort);
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
			Elf_dyn_entry(0, dyn, ndx, name,
			    osabi, ehdr->e_machine);
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
	const char	*fmt = NULL;

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

		if (fmt == NULL)
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
 * parse_note_t is used to track the state used by parse_note_entry()
 * between calls, and also to return the results of each call.
 */
typedef struct {
	/* pns_ fields track progress through the data */
	const char	*pns_file;	/* File name */
	Cache		*pns_cache;	/* Note section cache entry */
	size_t		pns_size;	/* # unprocessed data bytes */
	Word		*pns_data;	/* # to next unused data byte */

	/* pn_ fields return the results for a single call */
	Word		pn_namesz;	/* Value of note namesz field */
	Word		pn_descsz;	/* Value of note descsz field */
	Word		pn_type;	/* Value of note type field */
	const char	*pn_name;	/* if (namesz > 0) ptr to name bytes */
	const char	*pn_desc;	/* if (descsx > 0) ptr to data bytes */
} parse_note_t;

/*
 * Extract the various sub-parts of a note entry, and advance the
 * data pointer past it.
 *
 * entry:
 *	The state pns_ fields contain current values for the Note section
 *
 * exit:
 *	On success, True (1) is returned, the state pns_ fields have been
 *	advanced to point at the start of the next entry, and the information
 *	for the recovered note entry is found in the state pn_ fields.
 *
 *	On failure, False (0) is returned. The values contained in state
 *	are undefined.
 */
static int
parse_note_entry(parse_note_t *state)
{
	size_t	pad, noteoff;

	noteoff = (Word)state->pns_cache->c_data->d_size - state->pns_size;
	/*
	 * Make sure we can at least reference the 3 initial entries
	 * (4-byte words) of the note information block.
	 */
	if (state->pns_size >= (sizeof (Word) * 3)) {
		state->pns_size -= (sizeof (Word) * 3);
	} else {
		(void) fprintf(stderr, MSG_INTL(MSG_NOTE_BADDATASZ),
		    state->pns_file, state->pns_cache->c_name,
		    EC_WORD(noteoff));
		return (0);
	}

	/*
	 * Make sure any specified name string can be referenced.
	 */
	if ((state->pn_namesz = *state->pns_data++) != 0) {
		if (state->pns_size >= state->pn_namesz) {
			state->pns_size -= state->pn_namesz;
		} else {
			(void) fprintf(stderr, MSG_INTL(MSG_NOTE_BADNMSZ),
			    state->pns_file, state->pns_cache->c_name,
			    EC_WORD(noteoff), EC_WORD(state->pn_namesz));
			return (0);
		}
	}

	/*
	 * Make sure any specified descriptor can be referenced.
	 */
	if ((state->pn_descsz = *state->pns_data++) != 0) {
		/*
		 * If namesz isn't a 4-byte multiple, account for any
		 * padding that must exist before the descriptor.
		 */
		if ((pad = (state->pn_namesz & (sizeof (Word) - 1))) != 0) {
			pad = sizeof (Word) - pad;
			state->pns_size -= pad;
		}
		if (state->pns_size >= state->pn_descsz) {
			state->pns_size -= state->pn_descsz;
		} else {
			(void) fprintf(stderr, MSG_INTL(MSG_NOTE_BADDESZ),
			    state->pns_file, state->pns_cache->c_name,
			    EC_WORD(noteoff), EC_WORD(state->pn_namesz));
			return (0);
		}
	}

	state->pn_type = *state->pns_data++;

	/* Name */
	if (state->pn_namesz) {
		state->pn_name = (char *)state->pns_data;
		pad = (state->pn_namesz +
		    (sizeof (Word) - 1)) & ~(sizeof (Word) - 1);
		/* LINTED */
		state->pns_data = (Word *)(state->pn_name + pad);
	}

	/*
	 * If multiple information blocks exist within a .note section
	 * account for any padding that must exist before the next
	 * information block.
	 */
	if ((pad = (state->pn_descsz & (sizeof (Word) - 1))) != 0) {
		pad = sizeof (Word) - pad;
		if (state->pns_size > pad)
			state->pns_size -= pad;
	}

	/* Data */
	if (state->pn_descsz) {
		state->pn_desc = (const char *)state->pns_data;
		/* LINTED */
		state->pns_data = (Word *)(state->pn_desc +
		    state->pn_descsz + pad);
	}

	return (1);
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
	int		cnt = 0;
	int		is_corenote;
	int		do_swap;
	Conv_inv_buf_t	inv_buf;
	parse_note_t	pnstate;

	pnstate.pns_file = file;
	pnstate.pns_cache = cache;
	pnstate.pns_size = size;
	pnstate.pns_data = data;
	do_swap = _elf_sys_encoding() != ehdr->e_ident[EI_DATA];

	/*
	 * Print out a single `note' information block.
	 */
	while (pnstate.pns_size > 0) {

		if (parse_note_entry(&pnstate) == 0)
			return;

		/*
		 * Is this a Solaris core note? Such notes all have
		 * the name "CORE".
		 */
		is_corenote = (ehdr->e_type == ET_CORE) &&
		    (pnstate.pn_namesz == (MSG_STR_CORE_SIZE + 1)) &&
		    (strncmp(MSG_ORIG(MSG_STR_CORE), pnstate.pn_name,
		    MSG_STR_CORE_SIZE + 1) == 0);

		dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(0, MSG_INTL(MSG_FMT_NOTEENTNDX), EC_WORD(cnt));
		cnt++;
		dbg_print(0, MSG_ORIG(MSG_NOTE_NAMESZ),
		    EC_WORD(pnstate.pn_namesz));
		dbg_print(0, MSG_ORIG(MSG_NOTE_DESCSZ),
		    EC_WORD(pnstate.pn_descsz));

		if (is_corenote)
			dbg_print(0, MSG_ORIG(MSG_NOTE_TYPE_STR),
			    conv_cnote_type(pnstate.pn_type, 0, &inv_buf));
		else
			dbg_print(0, MSG_ORIG(MSG_NOTE_TYPE),
			    EC_WORD(pnstate.pn_type));
		if (pnstate.pn_namesz) {
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
			conv_str_to_c_literal(pnstate.pn_name,
			    pnstate.pn_namesz, c_literal_cb, NULL);
			dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
		}

		if (pnstate.pn_descsz) {
			int		hexdump = 1;

			/*
			 * If this is a core note, let the corenote()
			 * function handle it.
			 */
			if (is_corenote) {
				/* We only issue the bad arch error once */
				static int	badnote_done = 0;
				corenote_ret_t	corenote_ret;

				corenote_ret = corenote(ehdr->e_machine,
				    do_swap, pnstate.pn_type, pnstate.pn_desc,
				    pnstate.pn_descsz);
				switch (corenote_ret) {
				case CORENOTE_R_OK_DUMP:
					hexdump = 1;
					break;
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
				case CORENOTE_R_BADTYPE:
					(void) fprintf(stderr,
					    MSG_INTL(MSG_NOTE_BADCORETYPE),
					    file,
					    EC_WORD(pnstate.pn_type));
					break;

				}
			}

			/*
			 * The default thing when we don't understand
			 * the note data is to display it as hex bytes.
			 */
			if (hexdump) {
				dbg_print(0, MSG_ORIG(MSG_NOTE_DESC));
				dump_hex_bytes(pnstate.pn_desc,
				    pnstate.pn_descsz, 8, 4, 4);
			}
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
 * The Linux Standard Base defines a special note named .note.ABI-tag
 * that is used to maintain Linux ABI information. Presence of this section
 * is a strong indication that the object should be considered to be
 * ELFOSABI_LINUX.
 *
 * This function returns True (1) if such a note is seen, and False (0)
 * otherwise.
 */
static int
has_linux_abi_note(Cache *cache, Word shnum, const char *file)
{
	Word	cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		parse_note_t	pnstate;
		Cache		*_cache = &cache[cnt];
		Shdr		*shdr = _cache->c_shdr;

		/*
		 * Section must be SHT_NOTE, must have the name
		 * .note.ABI-tag, and must have data.
		 */
		if ((shdr->sh_type != SHT_NOTE) ||
		    (strcmp(MSG_ORIG(MSG_STR_NOTEABITAG),
		    _cache->c_name) != 0) || (_cache->c_data == NULL))
			continue;

		pnstate.pns_file = file;
		pnstate.pns_cache = _cache;
		pnstate.pns_size = _cache->c_data->d_size;
		pnstate.pns_data = (Word *)_cache->c_data->d_buf;

		while (pnstate.pns_size > 0) {
			Word *w;

			if (parse_note_entry(&pnstate) == 0)
				break;

			/*
			 * The type must be 1, and the name must be "GNU".
			 * The descsz must be at least 16 bytes.
			 */
			if ((pnstate.pn_type != 1) ||
			    (pnstate.pn_namesz != (MSG_STR_GNU_SIZE + 1)) ||
			    (strncmp(MSG_ORIG(MSG_STR_GNU), pnstate.pn_name,
			    MSG_STR_CORE_SIZE + 1) != 0) ||
			    (pnstate.pn_descsz < 16))
				continue;

			/*
			 * desc contains 4 32-bit fields. Field 0 must be 0,
			 * indicating Linux. The second, third, and fourth
			 * fields represent the earliest Linux kernel
			 * version compatible with this object.
			 */
			/*LINTED*/
			w = (Word *) pnstate.pn_desc;
			if (*w == 0)
				return (1);
		}
	}

	return (0);
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
		Cache		*_cache = &cache[scnt];
		Shdr		*shdr = _cache->c_shdr;
		Word		*grpdata, gcnt, grpcnt, symnum, unknown;
		Cache		*symsec, *strsec;
		Sym		*syms, *sym;
		char		flgstrbuf[MSG_GRP_COMDAT_SIZE + 10];
		const char	*grpnam;

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

		/*
		 * The GNU assembler can use section symbols as the signature
		 * symbol as described by this comment in the gold linker
		 * (found via google):
		 *
		 *	It seems that some versions of gas will create a
		 *	section group associated with a section symbol, and
		 *	then fail to give a name to the section symbol.  In
		 *	such a case, use the name of the section.
		 *
		 * In order to support such objects, we do the same.
		 */
		grpnam = string(_cache, 0, strsec, file, sym->st_name);
		if (((sym->st_name == 0) || (*grpnam == '\0')) &&
		    (ELF_ST_TYPE(sym->st_info) == STT_SECTION))
			grpnam = cache[sym->st_shndx].c_name;

		dbg_print(0, MSG_INTL(MSG_GRP_SIGNATURE), flgstrbuf,
		    demangle(grpnam, flags));

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

	if (symlookup(MSG_ORIG(MSG_SYM_GOT), cache, shnum, &gotsym, NULL,
	    symtab, file))
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
	char		*names = NULL;
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

	} else if ((names = data->d_buf) == NULL)
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
		    (_cache->c_data != NULL) &&
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



/*
 * Generate a cache of section headers and related information
 * for use by the rest of elfdump. If requested (or the file
 * contains no section headers), we generate a fake set of
 * headers from the information accessible from the program headers.
 * Otherwise, we use the real section headers contained in the file.
 */
static int
create_cache(const char *file, int fd, Elf *elf, Ehdr *ehdr, Cache **cache,
    size_t shstrndx, size_t *shnum, uint_t *flags)
{
	/*
	 * If there are no section headers, then resort to synthesizing
	 * section headers from the program headers. This is normally
	 * only done by explicit request, but in this case there's no
	 * reason not to go ahead, since the alternative is simply to quit.
	 */
	if ((*shnum <= 1) && ((*flags & FLG_CTL_FAKESHDR) == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_NOSHDR), file);
		*flags |= FLG_CTL_FAKESHDR;
	}

	if (*flags & FLG_CTL_FAKESHDR) {
		if (fake_shdr_cache(file, fd, elf, ehdr, cache, shnum) == 0)
			return (0);
	} else {
		if (shdr_cache(file, elf, ehdr, shstrndx, *shnum,
		    cache, *flags) == 0)
			return (0);
	}

	return (1);
}

int
regular(const char *file, int fd, Elf *elf, uint_t flags,
    const char *wname, int wfd, uchar_t osabi)
{
	enum { CACHE_NEEDED, CACHE_OK, CACHE_FAIL} cache_state = CACHE_NEEDED;
	Elf_Scn		*scn;
	Ehdr		*ehdr;
	size_t		ndx, shstrndx, shnum, phnum;
	Shdr		*shdr;
	Cache		*cache;
	VERSYM_STATE	versym = { 0 };
	int		ret = 0;
	int		addr_align;

	if ((ehdr = elf_getehdr(elf)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETEHDR));
		return (ret);
	}

	if (elf_getshdrnum(elf, &shnum) == -1) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHDRNUM));
		return (ret);
	}

	if (elf_getshdrstrndx(elf, &shstrndx) == -1) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHDRSTRNDX));
		return (ret);
	}

	if (elf_getphdrnum(elf, &phnum) == -1) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHDRNUM));
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
		shdr = NULL;

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
	 * Determine the Operating System ABI (osabi) we will use to
	 * interpret the object.
	 */
	if (flags & FLG_CTL_OSABI) {
		/*
		 * If the user explicitly specifies '-O none', we need
		 * to display a completely generic view of the file.
		 * However, libconv is written to assume that ELFOSABI_NONE
		 * is equivalent to ELFOSABI_SOLARIS. To get the desired
		 * effect, we use an osabi that libconv has no knowledge of.
		 */
		if (osabi == ELFOSABI_NONE)
			osabi = ELFOSABI_UNKNOWN4;
	} else {
		/* Determine osabi from file */
		osabi = ehdr->e_ident[EI_OSABI];
		if (osabi == ELFOSABI_NONE) {
			/*
			 * Chicken/Egg scenario:
			 *
			 * Ideally, we wait to create the section header cache
			 * until after the program headers are printed. If we
			 * only output program headers, we can skip building
			 * the cache entirely.
			 *
			 * Proper interpretation of program headers requires
			 * the osabi, which is supposed to be in the ELF header.
			 * However, many systems (Solaris and Linux included)
			 * have a history of setting the osabi to the generic
			 * SysV ABI (ELFOSABI_NONE). We assume ELFOSABI_SOLARIS
			 * in such cases, but would like to check the object
			 * to see if it has a Linux .note.ABI-tag section,
			 * which implies ELFOSABI_LINUX. This requires a
			 * section header cache.
			 *
			 * To break the cycle, we create section headers now
			 * if osabi is ELFOSABI_NONE, and later otherwise.
			 * If it succeeds, we use them, if not, we defer
			 * exiting until after the program headers are out.
			 */
			if (create_cache(file, fd, elf, ehdr, &cache,
			    shstrndx, &shnum, &flags) == 0) {
				cache_state = CACHE_FAIL;
			} else {
				cache_state = CACHE_OK;
				if (has_linux_abi_note(cache, shnum, file)) {
					Conv_inv_buf_t	ibuf1, ibuf2;

					(void) fprintf(stderr,
					    MSG_INTL(MSG_INFO_LINUXOSABI), file,
					    conv_ehdr_osabi(osabi, 0, &ibuf1),
					    conv_ehdr_osabi(ELFOSABI_LINUX,
					    0, &ibuf2));
					osabi = ELFOSABI_LINUX;
				}
			}
		}
		/*
		 * We treat ELFOSABI_NONE identically to ELFOSABI_SOLARIS.
		 * Mapping NONE to SOLARIS simplifies the required test.
		 */
		if (osabi == ELFOSABI_NONE)
			osabi = ELFOSABI_SOLARIS;
	}

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
			Elf_phdr(0, osabi, ehdr->e_machine, phdr);
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
	 * Everything from this point on requires section headers.
	 * If we have no section headers, there is no reason to continue.
	 *
	 * If we tried above to create the section header cache and failed,
	 * it is time to exit. Otherwise, create it if needed.
	 */
	switch (cache_state) {
	case CACHE_NEEDED:
		if (create_cache(file, fd, elf, ehdr, &cache, shstrndx,
		    &shnum, &flags) == 0)
			return (ret);
		break;
	case CACHE_OK:
		break;
	case CACHE_FAIL:
		return (ret);
	}
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
				 * to assume the meaning/format of a PROGBITS
				 * section based on its name. However, there
				 * are ABI mandated exceptions. Check for
				 * these special names.
				 */

				/* The ELF ABI specifies .interp and .got */
				if (strcmp(_cache->c_name,
				    MSG_ORIG(MSG_ELF_INTERP)) == 0) {
					flags |= FLG_SHOW_INTERP;
					break;
				}
				if (strcmp(_cache->c_name,
				    MSG_ORIG(MSG_ELF_GOT)) == 0) {
					flags |= FLG_SHOW_GOT;
					break;
				}
				/*
				 * The GNU compilers, and amd64 ABI, define
				 * .eh_frame and .eh_frame_hdr. The Sun
				 * C++ ABI defines .exception_ranges.
				 */
				if ((strncmp(_cache->c_name,
				    MSG_ORIG(MSG_SCN_FRM),
				    MSG_SCN_FRM_SIZE) == 0) ||
				    (strncmp(_cache->c_name,
				    MSG_ORIG(MSG_SCN_EXRANGE),
				    MSG_SCN_EXRANGE_SIZE) == 0)) {
					flags |= FLG_SHOW_UNWIND;
					break;
				}
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
		sections(file, cache, shnum, ehdr, osabi);

	if (flags & FLG_SHOW_INTERP)
		interp(file, cache, shnum, phnum, elf);

	if ((osabi == ELFOSABI_SOLARIS) || (osabi == ELFOSABI_LINUX))
		versions(cache, shnum, file, flags, &versym);

	if (flags & FLG_SHOW_SYMBOLS)
		symbols(cache, shnum, ehdr, osabi, &versym, file, flags);

	if ((flags & FLG_SHOW_SORT) && (osabi == ELFOSABI_SOLARIS))
		sunw_sort(cache, shnum, ehdr, osabi, &versym, file, flags);

	if (flags & FLG_SHOW_HASH)
		hash(cache, shnum, file, flags);

	if (flags & FLG_SHOW_GOT)
		got(cache, shnum, ehdr, file);

	if (flags & FLG_SHOW_GROUP)
		group(cache, shnum, file, flags);

	if (flags & FLG_SHOW_SYMINFO)
		syminfo(cache, shnum, ehdr, osabi, file);

	if (flags & FLG_SHOW_RELOC)
		reloc(cache, shnum, ehdr, file);

	if (flags & FLG_SHOW_DYNAMIC)
		dynamic(cache, shnum, ehdr, osabi, file);

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

	if ((flags & FLG_SHOW_MOVE) && (osabi == ELFOSABI_SOLARIS))
		move(cache, shnum, file, flags);

	if (flags & FLG_CALC_CHECKSUM)
		checksum(elf);

	if ((flags & FLG_SHOW_CAP) && (osabi == ELFOSABI_SOLARIS))
		cap(file, cache, shnum, phnum, ehdr, osabi, elf, flags);

	if ((flags & FLG_SHOW_UNWIND) &&
	    ((osabi == ELFOSABI_SOLARIS) || (osabi == ELFOSABI_LINUX)))
		unwind(cache, shnum, phnum, ehdr, osabi, file, elf, flags);


	/* Release the memory used to cache section headers */
done:
	if (flags & FLG_CTL_FAKESHDR)
		fake_shdr_cache_free(cache, shnum);
	else
		free(cache);

	return (ret);
}
