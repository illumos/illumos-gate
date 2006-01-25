/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
#include	<sys/param.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<libelf.h>
#include	<gelf.h>
#include	<link.h>
#include	<stdarg.h>
#include	<unistd.h>
#include	<libgen.h>
#include	<libintl.h>
#include	<locale.h>
#include	<errno.h>
#include	<strings.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_386.h>
#include	<sys/elf_amd64.h>
#include	<debug.h>
#include	<_debug.h>
#include	<conv.h>
#include	<msg.h>
#include	<dwarf.h>

#define	FLG_DYNAMIC	0x00000001
#define	FLG_EHDR	0x00000002
#define	FLG_INTERP	0x00000004
#define	FLG_SHDR	0x00000008
#define	FLG_NOTE	0x00000010
#define	FLG_PHDR	0x00000020
#define	FLG_RELOC	0x00000040
#define	FLG_SYMBOLS	0x00000080
#define	FLG_VERSIONS	0x00000100
#define	FLG_HASH	0x00000200
#define	FLG_GOT		0x00000400
#define	FLG_SYMINFO	0x00000800
#define	FLG_MOVE	0x00001000
#define	FLG_GROUP	0x00002000
#define	FLG_CAP		0x00004000
#define	FLG_UNWIND	0x00008000
#define	FLG_LONGNAME	0x00100000	/* not done by default */
#define	FLG_CHECKSUM	0x00200000	/* not done by default */
#define	FLG_DEMANGLE	0x00400000	/* not done by default */

#define	FLG_EVERYTHING	0x000fffff

#define	IAM_SPARC(X)	\
	((X == EM_SPARC) || (X == EM_SPARC32PLUS) || (X == EM_SPARCV9))
#define	IAM_INTEL(X)	\
	(X == EM_386)

#define	MAXNDXSIZE	10

typedef struct cache {
	GElf_Shdr	c_shdr;
	Elf_Data	*c_data;
	char		*c_name;
} Cache;

typedef struct got_info {
	GElf_Word	g_rshtype;	/* it will never happen, but */
					/* support mixed relocations */
	GElf_Rela	g_rela;
	const char	*g_symname;
} Got_info;

static const Cache	_cache_init = {{0}, NULL, NULL};

const char *
_elfdump_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}

/*
 * Determine whether a symbol name should be demangled.
 */
static const char *
demangle(const char *name, uint32_t flags)
{
	if (flags & FLG_DEMANGLE)
		return (Gelf_sym_dem(name));
	else
		return ((char *)name);
}


/*
 * Define our own printing routine.  All Elf routines referenced call upon
 * this routine to carry out the actual printing.
 */
/*PRINTFLIKE1*/
void
dbg_print(const char *format, ...)
{
	va_list		ap;

	va_start(ap, format);
	(void) vprintf(format, ap);
	(void) printf(MSG_ORIG(MSG_STR_NL));
	va_end(ap);
}

/*
 * Just like dbg_print - except that it does not insert
 * a newline at the end.  Can be used for printing tables
 * and such.
 */
/*PRINTFLIKE1*/
void
dbg_printf(const char *format, ...)
{
	va_list	    ap;
	va_start(ap, format);
	(void) vprintf(format, ap);
	va_end(ap);
}



/*
 * Define our own standard error routine.
 */
static void
failure(const char *file, const char *func)
{
	(void) fprintf(stderr, MSG_INTL(MSG_ERR_FAILURE),
	    file, func, elf_errmsg(elf_errno()));
	(void) fflush(stderr);
}


/*
 * Focal point for verifying symbol names.
 */
static const char *
string(Cache *refsec, GElf_Word ndx, Cache *strsec, const char *file,
    ulong_t name)
{
	static Cache	*osec = 0;
	static int	nostr;

	const char	*strs = (char *)strsec->c_data->d_buf;
	ulong_t		strn = strsec->c_data->d_size;

	/*
	 * Only print a diagnoistic regarding an empty string table once per
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
				(void) fflush(stderr);
				nostr++;
			}
		} else {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSTOFF),
			    file, refsec->c_name, ndx, strsec->c_name,
			    EC_XWORD(name), EC_XWORD(strn - 1));
			(void) fflush(stderr);
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
 * Lookup a symbol and set Sym accordingly.
 *
 * Returns:
 *	1 - symbol found
 *	0 - symbol not found
 */
static int
symlookup(const char *name, Cache *cache, GElf_Word shnum, GElf_Sym *sym,
    Cache *symtab, const char *file)
{
	GElf_Shdr *	shdr;
	GElf_Word	symn, cnt;

	if (symtab == 0)
		return (0);

	shdr = &symtab->c_shdr;
	/*
	 * Determine the symbol data and number.
	 */
	if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, symtab->c_name);
		(void) fflush(stderr);
		return (0);
	}
	/* LINTED */
	symn = (GElf_Word)(shdr->sh_size / shdr->sh_entsize);

	/*
	 * Get the associated string table section.
	 */
	if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
		    file, symtab->c_name, EC_XWORD(shdr->sh_link));
		(void) fflush(stderr);
		return (0);
	}

	/*
	 * Loop through the symbol table to find a match.
	 */
	for (cnt = 0; cnt < symn; cnt++) {
		GElf_Sym	tsym;
		const char	*sname;

		if (gelf_getsym(symtab->c_data, cnt, &tsym) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSYM),
			    file, symtab->c_name, elf_errmsg(0));
			(void) fflush(stderr);
			return (0);
		}

		sname = string(symtab, cnt, &cache[shdr->sh_link], file,
		    tsym.st_name);

		if (strcmp(name, sname) == 0) {
			*sym = tsym;
			return (1);
		}
	}
	return (0);
}

/*
 * The full usage message
 */
static void
detail_usage()
{
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL1));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL2));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL3));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL4));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL5));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL6));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL7));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL8));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL9));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL9_1));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL10));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL11));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL12));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL13));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL14));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL15));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL16));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL17));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL18));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL19));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL20));
	(void) fflush(stderr);
}

/*
 * Print section headers.
 */
static void
sections(const char *file, Cache *cache, GElf_Word shnum, GElf_Word phnum,
    GElf_Ehdr *ehdr, const char *name)
{
	GElf_Word	cnt;
	Cache *		_cache;

	for (cnt = 1; cnt < shnum; cnt++) {
		GElf_Shdr	*shdr;
		const char	*sname;

		_cache = &cache[cnt];
		sname = _cache->c_name;
		if (name && strcmp(name, sname))
			continue;

		/*
		 * Although numerous section header entries can be zero, it's
		 * usually a sign of trouble if the name or type are zero.
		 */
		shdr = &_cache->c_shdr;
		if (shdr->sh_type == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHTYPE),
			    file, sname, EC_XWORD(shdr->sh_type));
			(void) fflush(stderr);
		}
		if (shdr->sh_name == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHNAME),
			    file, sname, EC_XWORD(shdr->sh_name));
			(void) fflush(stderr);

			/*
			 * Use the empty string, rather than the fabricated
			 * name for the section output.
			 */
			sname = MSG_ORIG(MSG_STR_EMPTY);
		}

		/*
		 * Identify any sections that are suspicious.  A .got section
		 * shouldn't exist in a relocatable object.
		 */
		if (ehdr->e_type == ET_REL) {
			if (strncmp(sname, MSG_ORIG(MSG_ELF_GOT),
			    MSG_ELF_GOT_SIZE) == 0) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_GOT_UNEXPECTED), file, sname);
				(void) fflush(stderr);
			}
		}

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		/* LINTED */
		dbg_print(MSG_INTL(MSG_ELF_SHDR), (uint_t)cnt, sname);
		Gelf_shdr_entry(ehdr->e_machine, shdr);
	}
}

static void
unwind(Cache *cache, GElf_Word shnum, GElf_Word phnum, GElf_Ehdr *ehdr,
    const char *name, const char *file, Elf *elf)
{
	GElf_Word	cnt;
	GElf_Phdr	unwind_phdr;
	/*
	 * For the moment - UNWIND is only relevant for
	 * a AMD64 object
	 */
	if (ehdr->e_machine != EM_AMD64)
	    return;

	unwind_phdr.p_type = PT_NULL;

	for (cnt = 0; cnt < phnum; cnt++) {
		GElf_Phdr	phdr;

		if (gelf_getphdr(elf, cnt, &phdr) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
			return;
		}

		if (phdr.p_type == PT_SUNW_UNWIND) {
			unwind_phdr = phdr;
			break;
		}
	}


	for (cnt = 1; cnt < shnum; cnt++) {
		Cache		*_cache;
		GElf_Shdr	*shdr;
		unsigned char	*data;
		size_t		datasize;
		uint64_t	off, ndx;


		_cache = &cache[cnt];
		shdr = &_cache->c_shdr;
		/*
		 * XX64 - this is a strmcp() just to find the gcc
		 *	  produced sections.  Soon gcc should be
		 *	  settng the section type - and we'll not need
		 *	  this strcmp().
		 */
		if ((shdr->sh_type != SHT_AMD64_UNWIND) &&
		    (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRM),
		    MSG_SCN_FRM_SIZE) != 0) &&
		    (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRMHDR),
		    MSG_SCN_FRMHDR_SIZE) != 0))
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_UNWIND), _cache->c_name);

		data = (unsigned char *)(_cache->c_data->d_buf);
		datasize = _cache->c_data->d_size;
		off = 0;

		/*
		 * Is this a .eh_frame_hdr
		 */
		if (((unwind_phdr.p_type == PT_SUNW_UNWIND) &&
		    (shdr->sh_addr == unwind_phdr.p_vaddr)) ||
		    (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRMHDR),
			MSG_SCN_FRMHDR_SIZE) == 0)) {
			    uint_t	vers;
			    uint_t	frame_ptr_enc;
			    uint64_t	frame_ptr;
			    uint_t	fde_cnt_enc;
			    uint64_t	fde_cnt;
			    uint_t	table_enc;
			    uint64_t	tabndx;

			    dbg_print(MSG_ORIG(MSG_UNW_FRMHDR));
			    ndx = 0;

			    vers = data[ndx++];
			    frame_ptr_enc = data[ndx++];
			    fde_cnt_enc = data[ndx++];
			    table_enc = data[ndx++];

			    dbg_print(MSG_ORIG(MSG_UNW_FRMVERS), vers);

			    frame_ptr = dwarf_ehe_extract(data,
				&ndx, frame_ptr_enc, ehdr->e_ident,
				shdr->sh_addr + ndx);

			    dbg_print(MSG_ORIG(MSG_UNW_FRPTRENC),
				conv_dwarf_ehe_str(frame_ptr_enc),
				frame_ptr);

			    fde_cnt = dwarf_ehe_extract(data,
				&ndx, fde_cnt_enc, ehdr->e_ident,
				shdr->sh_addr + ndx);
			    dbg_print(MSG_ORIG(MSG_UNW_FDCNENC),
				    conv_dwarf_ehe_str(fde_cnt_enc),
				    fde_cnt);
			    dbg_print(MSG_ORIG(MSG_UNW_TABENC),
				    conv_dwarf_ehe_str(table_enc));
			    dbg_print(MSG_ORIG(MSG_UNW_BINSRTAB1));
			    dbg_print(MSG_ORIG(MSG_UNW_BINSRTAB2));

			    for (tabndx = 0; tabndx < fde_cnt; tabndx++) {
				    uint64_t	init_loc;
				    uint64_t	fde_loc;
				    init_loc = dwarf_ehe_extract(data,
					&ndx, table_enc, ehdr->e_ident,
					shdr->sh_addr);
				    fde_loc = dwarf_ehe_extract(data,
					&ndx, table_enc, ehdr->e_ident,
					shdr->sh_addr);
				    dbg_print(MSG_ORIG(MSG_UNW_BINSRTABENT),
					init_loc, fde_loc);
			    }
			    continue;
		}

		/*
		 * Walk the Eh_frame's
		 */
		while (off < datasize) {
			uint_t		cieid, cielength, cieversion,
					cieretaddr;
			int		cieRflag, cieLflag,
					ciePflag, cieZflag;
			uint_t		length,	id;
			uint64_t	ciecalign, ciedalign;
			char		*cieaugstr;
			uint_t		cieaugndx;

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
			 * A CIE record has a id of '0', otherwise
			 * this is a FDE entry and the 'id' is the
			 * CIE pointer.
			 */
			if (id == 0) {
				uint64_t    persVal;
				cielength = length;
				cieid = id;

				cieLflag = 0;
				ciePflag = 0;
				cieRflag = 0;
				cieZflag = 0;

				dbg_print(MSG_ORIG(MSG_UNW_CIE),
				    shdr->sh_addr + off);
				dbg_print(MSG_ORIG(MSG_UNW_CIELNGTH),
				    cielength, cieid);
				cieversion = data[off + ndx];
				ndx += 1;
				cieaugstr = (char *)(&data[off + ndx]);
				ndx += strlen(cieaugstr) + 1;
				dbg_print(MSG_ORIG(MSG_UNW_CIEVERS),
					cieversion, cieaugstr);
				ciecalign = uleb_extract(&data[off], &ndx);
				ciedalign = sleb_extract(&data[off], &ndx);
				cieretaddr = data[off + ndx];
				ndx += 1;
				dbg_print(MSG_ORIG(MSG_UNW_CIECALGN),
				    ciecalign, ciedalign, cieretaddr);

				if (cieaugstr[0])
				    dbg_print(MSG_ORIG(MSG_UNW_CIEAUXVAL));
				for (cieaugndx = 0; cieaugstr[cieaugndx];
				    cieaugndx++) {
					uint_t	val;
					switch (cieaugstr[cieaugndx]) {
					case 'z':
					    val = uleb_extract(&data[off],
						&ndx);
					    dbg_print(
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
					    dbg_print(
						MSG_ORIG(MSG_UNW_CIEAUXPERS),
						ciePflag,
						conv_dwarf_ehe_str(ciePflag),
						EC_XWORD(persVal));
					    break;
					case 'R':
					    val = data[off + ndx];
					    ndx += 1;
					    dbg_print(
						MSG_ORIG(MSG_UNW_CIEAUXCENC),
						val, conv_dwarf_ehe_str(val));
					    cieRflag = val;
					    break;
					case 'L':
					    val = data[off + ndx];
					    ndx += 1;
					    dbg_print(
						MSG_ORIG(MSG_UNW_CIEAUXLSDA),
						val, conv_dwarf_ehe_str(val));
					    cieLflag = val;
					    break;
					default:
					    dbg_print(
						MSG_ORIG(MSG_UNW_CIEAUXUNEC),
						cieaugstr[cieaugndx]);
					    break;
					}
				}
				if ((cielength + 4) > ndx) {
					uint_t	    cnt;
					dbg_printf(MSG_ORIG(MSG_UNW_CIECFI));
					cnt = 0;
					while (ndx < (cielength + 4)) {
						if ((cnt++ % 8) == 0) {
						    dbg_printf(
						    MSG_ORIG(MSG_UNW_CIECFI1));
						}
						dbg_printf(
						    MSG_ORIG(MSG_UNW_CIECFI2),
						    data[off + ndx++]);
					}
					dbg_print(MSG_ORIG(MSG_STR_EMPTY));
				}
				off += cielength + 4;
			} else {
				uint_t	    fdelength = length;
				int	    fdecieptr = id;
				uint64_t    fdeinitloc, fdeaddrrange;

				dbg_print(MSG_ORIG(MSG_UNW_FDE),
				    shdr->sh_addr + off);
				dbg_print(MSG_ORIG(MSG_UNW_FDELNGTH),
				    fdelength, fdecieptr);
				fdeinitloc = dwarf_ehe_extract(&data[off],
				    &ndx, cieRflag, ehdr->e_ident,
				    shdr->sh_addr + off + ndx);
				fdeaddrrange = dwarf_ehe_extract(&data[off],
				    &ndx, (cieRflag & ~DW_EH_PE_pcrel),
				    ehdr->e_ident,
				    shdr->sh_addr + off + ndx);
				dbg_print(MSG_ORIG(MSG_UNW_FDEINITLOC),
				    fdeinitloc, fdeaddrrange);
				if (cieaugstr[0])
					dbg_print(MSG_ORIG(MSG_UNW_FDEAUXVAL));
				if (cieZflag) {
					uint64_t    val;
					val = uleb_extract(&data[off], &ndx);
					dbg_print(
					    MSG_ORIG(MSG_UNW_FDEAUXSIZE), val);
					if (val & cieLflag) {
					    fdeinitloc = dwarf_ehe_extract(
						&data[off], &ndx, cieLflag,
						ehdr->e_ident,
						shdr->sh_addr + off + ndx);
					    dbg_print(
						MSG_ORIG(MSG_UNW_FDEAUXLSDA),
						val);
					}
				}
				if ((fdelength + 4) > ndx) {
					uint_t	    cnt;
					dbg_printf(MSG_ORIG(MSG_UNW_FDECFI));
					cnt = 0;
					while (ndx < (fdelength + 4)) {
						if ((cnt++ % 8) == 0) {
						    dbg_printf(
						    MSG_ORIG(MSG_UNW_FDECFI1));
						}
						dbg_printf(
						MSG_ORIG(MSG_UNW_FDECFI2),
						data[off + ndx++]);
					}
					dbg_print(MSG_ORIG(MSG_STR_EMPTY));
				}

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
cap(const char *file, Cache *cache, GElf_Word shnum, GElf_Word phnum,
    GElf_Ehdr *ehdr, Elf *elf)
{
	GElf_Word	cnt;
	GElf_Shdr *	cshdr = 0;
	Cache *		ccache;
	Elf64_Off	cphdr_off = 0;
	Elf64_Xword	cphdr_sz;

	/*
	 * Determine if a hardware/software capabilities header exists.
	 */
	for (cnt = 0; cnt < phnum; cnt++) {
		GElf_Phdr	phdr;

		if (gelf_getphdr(elf, cnt, &phdr) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
			return;
		}

		if (phdr.p_type == PT_SUNWCAP) {
			cphdr_off = phdr.p_offset;
			cphdr_sz = phdr.p_filesz;
			break;
		}
	}

	/*
	 * Determine if a hardware/software capabilities section exists.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache *		_cache;
		GElf_Shdr	*shdr;

		_cache = &cache[cnt];
		shdr = &_cache->c_shdr;

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
		GElf_Word	ndx, capn;

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_CAP), ccache->c_name);

		Gelf_cap_title();

		/* LINTED */
		capn = (GElf_Word)(cshdr->sh_size / cshdr->sh_entsize);

		/* LINTED */
		for (ndx = 0; ndx < capn; ndx++) {
			GElf_Cap	cap;

			if (gelf_getcap(ccache->c_data, ndx, &cap) == NULL) {
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADCAP),
				    file, ccache->c_name, elf_errmsg(0));
				(void) fflush(stderr);
				return;
			}
			if (cap.c_tag != CA_SUNW_NULL)
				Gelf_cap_print(&cap, ndx, ehdr->e_machine);
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
interp(const char *file, Cache *cache, GElf_Word shnum, GElf_Word phnum,
    GElf_Ehdr *ehdr, Elf *elf)
{
	GElf_Word	cnt;
	GElf_Shdr *	ishdr = 0;
	Cache *		icache;
	Elf64_Off	iphdr_off = 0;
	Elf64_Xword	iphdr_sz;

	/*
	 * Determine if an interp header exists.
	 */
	for (cnt = 0; cnt < phnum; cnt++) {
		GElf_Phdr	phdr;

		if (gelf_getphdr(elf, cnt, &phdr) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
			return;
		}

		if (phdr.p_type == PT_INTERP) {
			iphdr_off = phdr.p_offset;
			iphdr_sz = phdr.p_filesz;
			break;
		}
	}

	if (iphdr_off == 0)
		return;

	/*
	 * Determine if an interp section exists.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache *		_cache;
		GElf_Shdr	*shdr;

		_cache = &cache[cnt];
		shdr = &_cache->c_shdr;

		/*
		 * Scan sections to find a section which contains the PT_INTERP
		 * string.  The target section can't be in a NOBITS section.
		 */
		if ((shdr->sh_type == SHT_NOBITS) ||
		    (iphdr_off < shdr->sh_offset) ||
		    (iphdr_off + iphdr_sz) > (shdr->sh_offset + shdr->sh_size))
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
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_INTERP), icache->c_name);
		dbg_print(MSG_ORIG(MSG_FMT_INDENT),
		    (char *)icache->c_data->d_buf +
		    (iphdr_off - ishdr->sh_offset));
	} else
		(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVINTERP1), file);

	/*
	 * If there are any inconsistences between the program header and
	 * section information, flag them.
	 */
	if (ishdr && ((iphdr_off != ishdr->sh_offset) ||
	    (iphdr_sz != ishdr->sh_size))) {
		(void) fprintf(stderr, MSG_INTL(MSG_WARN_INVINTERP2), file,
		    icache->c_name);
		(void) fflush(stderr);
	}
}

/*
 * Print the syminfo section.
 */
static void
syminfo(Cache *cache, GElf_Word shnum, const char *file)
{
	GElf_Shdr	*shdr;
	Elf_Data	*dsyms, *ddyn;
	GElf_Word	symn, cnt, ndx;
	Cache		*syminfo = 0;
	char		*sname;

	for (cnt = 1; cnt < shnum; cnt++) {
		if (cache[cnt].c_shdr.sh_type == SHT_SUNW_syminfo) {
			syminfo = &cache[cnt];
			break;
		}
	}
	if (syminfo == 0)
		return;

	shdr = &syminfo->c_shdr;
	/*
	 * Determine the symbol info data and number.
	 */
	if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, syminfo->c_name);
		(void) fflush(stderr);
		return;
	}
	/* LINTED */
	symn = (GElf_Word)(shdr->sh_size / shdr->sh_entsize);

	/*
	 * Get the data buffer of the associated dynamic section.
	 */
	if ((shdr->sh_info == 0) || (shdr->sh_info >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHINFO),
		    file, syminfo->c_name, EC_XWORD(shdr->sh_info));
		(void) fflush(stderr);
		return;
	}
	ddyn = cache[shdr->sh_info].c_data;
	if (ddyn->d_buf == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, cache[shdr->sh_info].c_name);
		(void) fflush(stderr);
		return;
	}

	/*
	 * Get the data buffer of the associated symbol table.
	 */
	if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
		    file, syminfo->c_name, EC_XWORD(shdr->sh_link));
		(void) fflush(stderr);
		return;
	}
	dsyms = cache[shdr->sh_link].c_data;
	if (dsyms->d_buf == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, cache[shdr->sh_link].c_name);
		(void) fflush(stderr);
		return;
	}

	sname = cache[shdr->sh_link].c_name;
	shdr = &cache[shdr->sh_link].c_shdr;
	/*
	 * Get the associated string table section.
	 */
	if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
		    file, sname, EC_XWORD(shdr->sh_link));
		(void) fflush(stderr);
		return;
	}

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_ELF_SCN_SYMINFO), syminfo->c_name);
	Gelf_syminfo_title();

	for (ndx = 1; ndx < symn; ndx++) {
		GElf_Syminfo 	gsip;
		GElf_Sym 	gsym;
		GElf_Dyn	gdyn;
		const char	*needed, *sname;

		if (gelf_getsyminfo(syminfo->c_data, ndx, &gsip) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_SIBADCOUNT),
			    file, syminfo->c_name, ndx);
			(void) fflush(stderr);
			return;
		}
		if ((gsip.si_flags == 0) && (gsip.si_boundto == 0))
			continue;

		if (gelf_getsym(dsyms, ndx, &gsym) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSYM),
			    file, syminfo->c_name, elf_errmsg(0));
			(void) fflush(stderr);
			return;
		}

		sname = string(syminfo, cnt, &cache[shdr->sh_link], file,
		    gsym.st_name);
		needed = 0;

		if (gsip.si_boundto < SYMINFO_BT_LOWRESERVE) {
			if (gelf_getdyn(ddyn, gsip.si_boundto, &gdyn) == 0) {
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADDYN),
				    file, syminfo->c_name, gsip.si_boundto);
				(void) fflush(stderr);
				return;
			}
			needed = string(syminfo, gsip.si_boundto,
			    &cache[shdr->sh_link], file, gdyn.d_un.d_val);
		}

		Gelf_syminfo_entry(ndx, &gsip, sname, needed);
	}
}

/*
 * Print version definition section entries.
 */
static void
version_def(GElf_Verdef *vdf, GElf_Word shnum, Cache *vcache, Cache *scache,
    const char *file)
{
	GElf_Word	cnt;
	char		index[MAXNDXSIZE];

	Gelf_ver_def_title();

	for (cnt = 1; cnt <= shnum; cnt++,
	    vdf = (GElf_Verdef *)((uintptr_t)vdf + vdf->vd_next)) {

		GElf_Half	vcnt = vdf->vd_cnt - 1;
		GElf_Half	ndx = vdf->vd_ndx;
		GElf_Verdaux	*vdap = (GElf_Verdaux *)
				    ((uintptr_t)vdf + vdf->vd_aux);
		const char	*name, *dep;

		/*
		 * Obtain the name and first dependency (if any).
		 */
		name = string(vcache, cnt, scache, file, vdap->vda_name);
		vdap = (GElf_Verdaux *)((uintptr_t)vdap + vdap->vda_next);
		if (vcnt)
			dep = string(vcache, cnt, scache, file, vdap->vda_name);
		else
			dep = MSG_ORIG(MSG_STR_EMPTY);

		(void) snprintf(index, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INDEX),
		    EC_XWORD(ndx));
		Gelf_ver_line_1(index, name, dep,
		    conv_verflg_str(vdf->vd_flags));

		/*
		 * Print any additional dependencies.
		 */
		if (vcnt) {
			vdap = (GElf_Verdaux *)((uintptr_t)vdap +
				vdap->vda_next);
			for (vcnt--; vcnt; vcnt--,
			    vdap = (GElf_Verdaux *)((uintptr_t)vdap +
			    vdap->vda_next)) {
				dep = string(vcache, cnt, scache, file,
				    vdap->vda_name);
				Gelf_ver_line_2(MSG_ORIG(MSG_STR_EMPTY), dep);
			}
		}
	}
}

/*
 * Print a version needed section entries.
 */
static void
version_need(GElf_Verneed *vnd, GElf_Word shnum, Cache *vcache, Cache *scache,
    const char *file)
{
	GElf_Word	cnt;

	Gelf_ver_need_title();

	for (cnt = 1; cnt <= shnum; cnt++,
	    vnd = (GElf_Verneed *)((uintptr_t)vnd + vnd->vn_next)) {

		GElf_Half	vcnt = vnd->vn_cnt;
		GElf_Vernaux	*vnap = (GElf_Vernaux *)((uintptr_t)vnd +
			vnd->vn_aux);
		const char	*name, *dep;

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

		Gelf_ver_line_1(MSG_ORIG(MSG_STR_EMPTY), name, dep,
		    conv_verflg_str(vnap->vna_flags));

		/*
		 * Print any additional version dependencies.
		 */
		if (vcnt) {
			vnap = (GElf_Vernaux *)((uintptr_t)vnap +
				vnap->vna_next);
			for (vcnt--; vcnt; vcnt--,
			    vnap = (GElf_Vernaux *)((uintptr_t)vnap +
			    vnap->vna_next)) {
				dep = string(vcache, cnt, scache, file,
				    vnap->vna_name);
				Gelf_ver_line_3(MSG_ORIG(MSG_STR_EMPTY), dep,
				    conv_verflg_str(vnap->vna_flags));
			}
		}
	}
}

/*
 * Search for any verion sections - the Versym output is possibly
 * used by the symbols() printing.  If VERSYM is specified - then
 * display the version information.
 */
static Cache *
versions(Cache *cache, GElf_Word shnum, const char *file, uint32_t flags)
{
	GElf_Word	cnt;
	Cache		*versymcache = 0;

	for (cnt = 1; cnt < shnum; cnt++) {
		void *		ver;
		uint_t		num;
		Cache *		_cache = &cache[cnt];
		GElf_Shdr *	shdr = &_cache->c_shdr;

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
			    file, _cache->c_name);
			(void) fflush(stderr);
			continue;
		}
		if ((num = shdr->sh_info) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHINFO),
			    file, _cache->c_name, EC_XWORD(shdr->sh_info));
			(void) fflush(stderr);
			continue;
		}

		/*
		 * Get the data buffer for the associated string table.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		if (shdr->sh_type == SHT_SUNW_verdef) {
			dbg_print(MSG_INTL(MSG_ELF_SCN_VERDEF),
			    _cache->c_name);
			version_def((GElf_Verdef *)ver, num, _cache,
			    &cache[shdr->sh_link], file);
		} else if (shdr->sh_type == SHT_SUNW_verneed) {
			dbg_print(MSG_INTL(MSG_ELF_SCN_VERNEED),
			    _cache->c_name);
			version_need((GElf_Verneed *)ver, num, _cache,
			    &cache[shdr->sh_link], file);
		}
	}
	return (versymcache);
}

/*
 * Search for and process any symbol tables.
 */
static void
symbols(Cache *cache, GElf_Word shnum, GElf_Word phnum, GElf_Ehdr *ehdr,
    const char *name, Cache *versymcache, const char *file)
{
	GElf_Word	cnt;
	char		is_core = (ehdr->e_type == ET_CORE);

	for (cnt = 1; cnt < shnum; cnt++) {
		GElf_Sym 	sym;
		GElf_Word	symn, _cnt;
		GElf_Versym	*versym;
		Cache		*_cache = &cache[cnt];
		GElf_Shdr	*shdr = &_cache->c_shdr;
		Word		*symshndx;
		uint_t		nosymshndx;
		uint_t		nosyminshndx;

		if ((shdr->sh_type != SHT_SYMTAB) &&
		    (shdr->sh_type != SHT_DYNSYM))
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;

		/*
		 * Determine the symbol data and number.
		 */
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			(void) fflush(stderr);
			continue;
		}
		/* LINTED */
		symn = (GElf_Word)(shdr->sh_size / shdr->sh_entsize);

		/*
		 * Get the associated string table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}

		/*
		 * Determine if there is a associated Versym section
		 * with this Symbol Table.
		 */
		if (versymcache && (versymcache->c_shdr.sh_link == cnt))
			versym = versymcache->c_data->d_buf;
		else
			versym = 0;

		/*
		 * Loop through the symbol tables entries.
		 */
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_SYMTAB), _cache->c_name);
		Gelf_sym_table_title(ehdr, MSG_INTL(MSG_STR_INDEX),
		    MSG_INTL(MSG_STR_NAME));

		symshndx = 0;
		nosymshndx = 0;
		nosyminshndx = 0;
		for (_cnt = 0; _cnt < symn; _cnt++) {
			char		index[MAXNDXSIZE];
			char		*sec;
			const char	*sname;
			int		verndx;
			uchar_t		type;
			GElf_Shdr	*tshdr;
			Word		shndx;

			if (gelf_getsym(_cache->c_data, _cnt, &sym) == NULL) {
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSYM),
				    file, _cache->c_name, elf_errmsg(0));
				(void) fflush(stderr);
				break;
			}

			/*
			 * If we are using extended symbol indexes, find the
			 * corresponding SHN_SYMTAB_SHNDX table.
			 */
			if ((sym.st_shndx == SHN_XINDEX) &&
			    (symshndx == 0) && (nosymshndx == 0)) {
				Word	__cnt;

				for (__cnt = 1; __cnt < shnum; __cnt++) {
					Cache		*_cache = &cache[__cnt];
					GElf_Shdr	*shdr = &_cache->c_shdr;

					if ((shdr->sh_type !=
					    SHT_SYMTAB_SHNDX) ||
					    (shdr->sh_link != cnt))
						continue;
					if (shdr->sh_entsize)
						/* LINTED */
						nosyminshndx = (uint_t)
						shdr->sh_size/shdr->sh_entsize;
					if (nosyminshndx == 0)
						continue;
					symshndx = _cache->c_data->d_buf;
					break;
				}
				if (symshndx == 0)
					nosymshndx = 1;
			}

			/* LINTED */
			sname = string(_cache, _cnt, &cache[shdr->sh_link],
			    file, sym.st_name);

			tshdr = 0;
			sec = NULL;

			if (is_core)
				sec = (char *)MSG_INTL(MSG_STR_UNKNOWN);
			else if ((sym.st_shndx < SHN_LORESERVE) &&
			    (sym.st_shndx < shnum)) {
				shndx = sym.st_shndx;
				tshdr = &(cache[shndx].c_shdr);
				sec = cache[shndx].c_name;
			} else if (sym.st_shndx == SHN_XINDEX) {
				if (symshndx) {
					Word	_symshndx;

					if (_cnt > nosyminshndx) {
					    (void) fprintf(stderr,
						MSG_INTL(MSG_ERR_BADSYMXINDEX1),
						file, _cache->c_name,
						EC_WORD(_cnt));
					    (void) fflush(stderr);
					} else if ((_symshndx =
					    symshndx[_cnt]) > shnum) {
					    (void) fprintf(stderr,
						MSG_INTL(MSG_ERR_BADSYMXINDEX2),
						file, _cache->c_name,
						EC_WORD(_cnt),
						EC_WORD(_symshndx));
					    (void) fflush(stderr);
					} else {
					    shndx = _symshndx;
					    tshdr = &(cache[shndx].c_shdr);
					    sec = cache[shndx].c_name;
					}
				} else {
					(void) fprintf(stderr,
						MSG_INTL(MSG_ERR_BADSYMXINDEX3),
						file, _cache->c_name,
						EC_WORD(_cnt));
					(void) fflush(stderr);
				}
			} else if ((sym.st_shndx < SHN_LORESERVE) &&
			    (sym.st_shndx >= shnum)) {
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_BADSYM5),
					file, _cache->c_name,
					sname, sym.st_shndx);
				(void) fflush(stderr);
			}

			/*
			 * If versioning is available display the
			 * version index.
			 */
			if (versym)
				verndx = (int)versym[_cnt];
			else
				verndx = 0;

			/*
			 * Error checking for TLS.
			 */
			type = ELF_ST_TYPE(sym.st_info);
			if (type == STT_TLS) {
				if (tshdr &&
				    (sym.st_shndx != SHN_UNDEF) &&
				    ((tshdr->sh_flags & SHF_TLS) == 0)) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_BADSYM3), file,
					    _cache->c_name, sname);
					(void) fflush(stderr);
				}
			} else if ((type != STT_SECTION) && sym.st_size &&
			    tshdr && (tshdr->sh_flags & SHF_TLS)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYM4), file,
				    _cache->c_name, sname);
				(void) fflush(stderr);
			}

			/*
			 * If a symbol has size, then make sure the section it
			 * references is appropriate.  Note, UNDEF symbols that
			 * have a size, have been known to exist - ignore them.
			 */
			if (sym.st_size && shndx && tshdr &&
			    (tshdr->sh_size < sym.st_size)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSYM6), file,
				    _cache->c_name, sname, EC_WORD(shndx),
				    EC_XWORD(tshdr->sh_size),
				    EC_XWORD(sym.st_size));
				(void) fflush(stderr);
			}

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(_cnt));

			Gelf_sym_table_entry(index, ehdr, &sym, verndx, sec,
			    sname);
		}
	}
}

/*
 * Search for and process any relocation sections.
 */
static void
reloc(Cache *cache, GElf_Word shnum, GElf_Word phnum, GElf_Ehdr *ehdr,
    const char *name, const char *file, uint32_t flags)
{
	GElf_Word	cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		Word		type;
		ulong_t		numrels, entsize;
		int		ndx;
		Elf_Data	*dsyms;
		Cache		*_cache = &cache[cnt];
		GElf_Shdr	*shdr = &_cache->c_shdr;
		char		*sname;

		if (((type = shdr->sh_type) != SHT_RELA) &&
		    (type != SHT_REL))
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;

		/*
		 * Decide entry size
		 */
		if (((entsize = shdr->sh_entsize) == 0) ||
		    (entsize > shdr->sh_size)) {
			if (type == SHT_RELA)
				entsize = sizeof (GElf_Rela);
			else
				entsize = sizeof (GElf_Rel);
		}

		/*
		 * Determine the number of relocations available.
		 */
		if (shdr->sh_size == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			(void) fflush(stderr);
			continue;
		}
		numrels = shdr->sh_size / entsize;

		/*
		 * Get the data buffer for the associated symbol table.  Note
		 * that we've been known to create static binaries containing
		 * relocations against weak symbols, if these get stripped the
		 * relocation records can't make symbolic references.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}
		dsyms = cache[shdr->sh_link].c_data;
		if (dsyms->d_buf == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, cache[shdr->sh_link].c_name);
			(void) fflush(stderr);
			continue;
		}

		sname = cache[shdr->sh_link].c_name;
		shdr = &cache[shdr->sh_link].c_shdr;
		/*
		 * Get the associated string table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, sname, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}

		/*
		 * Loop through the relocation entries.
		 */
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_RELOC), _cache->c_name);
		if (type == SHT_RELA) {
			if (flags & FLG_LONGNAME)
				dbg_print(MSG_INTL(MSG_ELF_L_RELOC_RELA));
			else
				dbg_print(MSG_INTL(MSG_ELF_RELOC_RELA));
		} else {
			if (flags & FLG_LONGNAME)
				dbg_print(MSG_INTL(MSG_ELF_L_RELOC_REL));
			else
				dbg_print(MSG_INTL(MSG_ELF_RELOC_REL));
		}

		/* LINTED */
		for (ndx = 0; ndx < numrels; ndx++) {
			char		section[BUFSIZ];
			const char	*_name;
			GElf_Word	sndx;
			ulong_t		r_type;
			GElf_Sym	_sym;
			GElf_Rela	rela;

			/*
			 * Determine the symbol with which this relocation is
			 * associated.  If the symbol represents a section
			 * offset construct an appropriate string.
			 */
			if (type == SHT_RELA) {
				(void) gelf_getrela(_cache->c_data, ndx,
				    &rela);
			} else {
				(void) gelf_getrel(_cache->c_data, ndx,
				    (GElf_Rel*)&rela);
			}
			/* LINTED */
			sndx = (GElf_Word)GELF_R_SYM(rela.r_info);
			r_type = GELF_R_TYPE(rela.r_info);

			/* LINTED */
			if (gelf_getsym(dsyms, (int)sndx, &_sym) == NULL) {
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_RELBADSYMNDX),
				    file, elf_errmsg(0));
				(void) fflush(stderr);
				_name = MSG_INTL(MSG_STR_UNKNOWN);
			} else  {
				if ((GELF_ST_TYPE(_sym.st_info) ==
				    STT_SECTION) && (_sym.st_name == 0)) {
					if (flags & FLG_LONGNAME)
					    (void) snprintf(section, BUFSIZ,
						MSG_INTL(MSG_STR_L_SECTION),
						cache[_sym.st_shndx].c_name);
					else
					    (void) snprintf(section, BUFSIZ,
						MSG_INTL(MSG_STR_SECTION),
						cache[_sym.st_shndx].c_name);
					_name = (const char *)section;
				} else {
					/* LINTED */
					_name = string(_cache,
					    sndx, &cache[shdr->sh_link],
					    file, _sym.st_name);
				}
			}

			if ((sndx == 0) && ((IAM_SPARC(ehdr->e_machine) &&
			    ((r_type != R_SPARC_NONE) &&
			    (r_type != R_SPARC_REGISTER) &&
			    (r_type != R_SPARC_RELATIVE))) ||
			    ((IAM_INTEL(ehdr->e_machine) &&
			    ((r_type != R_386_NONE) &&
			    (r_type != R_386_RELATIVE)))))) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADREL1), file,
				    conv_reloc_type_str(ehdr->e_machine,
				    /* LINTED */
				    (uint_t)r_type));
				(void) fflush(stderr);
			}

			Gelf_reloc_entry(MSG_ORIG(MSG_STR_EMPTY),
			    ehdr->e_machine, type, (void *)&rela,
			    _cache->c_name, _name);
		}
	}
}

/*
 * Search for and process a .dynamic section.
 */
static void
dynamic(Cache *cache, GElf_Word shnum, GElf_Ehdr *ehdr, const char *file)
{
	GElf_Word	cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		GElf_Dyn	dyn;
		ulong_t		numdyn;
		int		ndx;
		Cache *		_cache = &cache[cnt];
		GElf_Shdr *	shdr = &_cache->c_shdr;

		if (shdr->sh_type != SHT_DYNAMIC)
			continue;

		/*
		 * Get the associated string table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}
		numdyn = shdr->sh_size / shdr->sh_entsize;

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_DYNAMIC), _cache->c_name);

		Gelf_dyn_title();

		/* LINTED */
		for (ndx = 0; ndx < numdyn; ++ndx) {
			const char	*name;

			(void) gelf_getdyn(_cache->c_data, ndx, &dyn);
			if (dyn.d_tag == DT_NULL)
				break;

			/*
			 * Print the information numerically, and if possible
			 * as a string.
			 */
			if ((dyn.d_tag == DT_NEEDED) ||
			    (dyn.d_tag == DT_SONAME) ||
			    (dyn.d_tag == DT_FILTER) ||
			    (dyn.d_tag == DT_AUXILIARY) ||
			    (dyn.d_tag == DT_CONFIG) ||
			    (dyn.d_tag == DT_RPATH) ||
			    (dyn.d_tag == DT_RUNPATH) ||
			    (dyn.d_tag == DT_USED) ||
			    (dyn.d_tag == DT_DEPAUDIT) ||
			    (dyn.d_tag == DT_AUDIT) ||
			    (dyn.d_tag == DT_SUNW_AUXILIARY) ||
			    (dyn.d_tag == DT_SUNW_FILTER))
				name = string(_cache, ndx,
				    &cache[shdr->sh_link], file,
				    dyn.d_un.d_ptr);
			else if (dyn.d_tag == DT_FLAGS)
			    /* LINTED */
			    name = conv_dynflag_str((Word)dyn.d_un.d_val);
			else if (dyn.d_tag == DT_FLAGS_1)
			    /* LINTED */
			    name = conv_dynflag_1_str((Word)dyn.d_un.d_val);
			else if (dyn.d_tag == DT_POSFLAG_1)
			    /* LINTED */
			    name = conv_dynposflag_1_str((Word)dyn.d_un.d_val);
			else if (dyn.d_tag == DT_FEATURE_1)
			    /* LINTED */
			    name = conv_dynfeature_1_str((Word)dyn.d_un.d_val);
			else if (dyn.d_tag == DT_DEPRECATED_SPARC_REGISTER)
			    name = MSG_INTL(MSG_STR_DEPRECATED);
			else
			    name = MSG_ORIG(MSG_STR_EMPTY);

			Gelf_dyn_print(&dyn, ndx, name, ehdr->e_machine);
		}
	}
}

/*
 * Search for and process a MOVE section.
 */
static void
move(Cache *cache, GElf_Word shnum, const char *name, const char *file,
    uint32_t flags)
{
	GElf_Word	cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		ulong_t		num, symn;
		int		ndx;
		Elf_Data	*dsyms;
		const char	*fmt;
		Cache		*_cache = &cache[cnt];
		GElf_Shdr	*shdr = &_cache->c_shdr;
		char		*sname;

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
			(void) fflush(stderr);
			continue;
		}
		num = shdr->sh_size / shdr->sh_entsize;

		/*
		 * Get the data buffer for the associated symbol table.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}
		dsyms = cache[shdr->sh_link].c_data;
		if (dsyms->d_buf == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, cache[shdr->sh_link].c_name);
			(void) fflush(stderr);
			continue;
		}

		sname = cache[shdr->sh_link].c_name;
		shdr = &cache[shdr->sh_link].c_shdr;

		/*
		 * Get the associated string table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, sname, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, sname);
			(void) fflush(stderr);
			continue;
		}
		symn = shdr->sh_size / shdr->sh_entsize;

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_MV_TITLE), _cache->c_name);

		fmt = MSG_INTL(MSG_MV_ENTRY);

		/* LINTED */
		for (ndx = 0; ndx < num; ndx++) {
			GElf_Move 	move;
			const char	*name;
			GElf_Sym	sym;
			char		sct[BUFSIZ];
			Word		shndx;

			if (gelf_getmove(_cache->c_data, ndx, &move) == NULL) {
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_BADMOVE),
					file, _cache->c_name, elf_errmsg(0));
				(void) fflush(stderr);
				break;
			}

			/*
			 * Check for null entries
			 */
			if ((move.m_info == 0) && (move.m_value == 0) &&
			    (move.m_poffset == 0) && (move.m_repeat == 0) &&
			    (move.m_stride == 0)) {
				dbg_print(fmt, EC_XWORD(move.m_poffset),
				    EC_XWORD(0), 0, 0, 0, EC_LWORD(0),
				    MSG_ORIG(MSG_STR_EMPTY));
				continue;
			}
			if ((GELF_M_SYM(move.m_info) == 0) ||
			    (GELF_M_SYM(move.m_info) >= symn)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADMINFO), file,
				    _cache->c_name, EC_XWORD(move.m_info));
				(void) fflush(stderr);
				dbg_print(fmt, EC_XWORD(move.m_poffset),
				    EC_XWORD(GELF_M_SYM(move.m_info)),
				    /* LINTED */
				    GELF_M_SIZE(move.m_info), move.m_repeat,
				    move.m_stride, EC_LWORD(move.m_value),
				    MSG_INTL(MSG_STR_UNKNOWN));
				continue;
			}

			if (gelf_getsym(dsyms,
			    /* LINTED */
			    (int)GELF_M_SYM(move.m_info), &sym) == NULL) {
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_MVBADSYMNDX),
				    file, elf_errmsg(0));
				(void) fflush(stderr);
				name = MSG_INTL(MSG_STR_UNKNOWN);
			} else {
				if ((GELF_ST_TYPE(sym.st_info) ==
				    STT_SECTION) && (sym.st_name == 0)) {
				    if (flags & FLG_LONGNAME)
					(void) snprintf(sct, BUFSIZ,
					    MSG_INTL(MSG_STR_L_SECTION),
					    cache[sym.st_shndx].c_name);
				    else
					(void) snprintf(sct, BUFSIZ,
					    MSG_INTL(MSG_STR_SECTION),
					    cache[sym.st_shndx].c_name);
					name = (const char *)sct;
				} else {
					name = demangle(string(_cache,
					    /* LINTED */
					    (GElf_Word)GELF_M_SYM(move.m_info),
					    &cache[shdr->sh_link], file,
					    sym.st_name), flags);
				}
			}

			/*
			 * Additional sanity check.
			 */
			shndx = sym.st_shndx;
			if (!((shndx == SHN_COMMON) ||
			    (((shndx >= 1) && (shndx <= shnum)) &&
			    (cache[shndx].c_shdr).sh_type == SHT_NOBITS))) {
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_BADSYM2), file,
					_cache->c_name, name);
				(void) fflush(stderr);
			}

			dbg_print(fmt, EC_XWORD(move.m_poffset),
			    EC_XWORD(GELF_M_SYM(move.m_info)),
			    /* LINTED */
			    GELF_M_SIZE(move.m_info), move.m_repeat,
			    move.m_stride, EC_LWORD(move.m_value), name);
		}
	}
}

/*
 * Traverse a note section analyzing each note information block.
 * The data buffers size is used to validate references before they are made,
 * and is decremented as each element is processed.
 */
void
note_entry(Cache *cache, Word *data, Word size, const char *file)
{
	Word	bsize = size;
	/*
	 * Print out a single `note' information block.
	 */
	while (size > 0) {
		Word	namesz, descsz, type, pad, noteoff;


		noteoff = bsize - size;
		/*
		 * Make sure we can at least reference the 3 initial entries
		 * (4-byte words) of the note information block.
		 */
		if (size >= (Word)(sizeof (Word) * 3))
			size -= (Word)(sizeof (Word) * 3);
		else {
			(void) fprintf(stderr, MSG_INTL(MSG_NOTE_BADDATASIZE),
				file, cache->c_name, EC_WORD(noteoff));
			(void) fflush(stderr);
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
					MSG_INTL(MSG_NOTE_BADNMSIZE),
					file, cache->c_name, EC_WORD(noteoff),
					EC_WORD(namesz));
				(void) fflush(stderr);
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
			if ((pad = (namesz & (Word)(sizeof (Word) - 1))) != 0) {
				pad = (Word)sizeof (Word) - pad;
				size -= pad;
			}
			if (size >= descsz)
				size -= descsz;
			else {
				(void) fprintf(stderr,
					MSG_INTL(MSG_NOTE_BADDESIZE),
					file, cache->c_name, EC_WORD(noteoff),
					EC_WORD(namesz));
				(void) fflush(stderr);
				return;
			}
		}

		type = *data++;

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_ORIG(MSG_NOTE_TYPE), EC_WORD(type));

		dbg_print(MSG_ORIG(MSG_NOTE_NAMESZ), EC_WORD(namesz));
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
			dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		}

		/*
		 * If multiple information blocks exist within a .note section
		 * account for any padding that must exist before the next
		 * information block.
		 */
		if ((pad = (descsz & (Word)(sizeof (Word) - 1))) != 0) {
			pad = (Word)sizeof (Word) - pad;
			if (size > pad)
				size -= pad;
		}

		dbg_print(MSG_ORIG(MSG_NOTE_DESCSZ), EC_WORD(descsz));
		if (descsz) {
			int		ndx, byte, word;
			char		string[58], * str = string;
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
					dbg_print(MSG_ORIG(MSG_NOTE_DESC),
					    ndx, string);
					word = 0;
					ndx += 16;
					str = string;
				}
			}
			if (byte || word) {
				*str = '\0';
				dbg_print(MSG_ORIG(MSG_NOTE_DESC), ndx, string);
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
note(Cache *cache, GElf_Word shnum, const char *name, const char *file)
{
	GElf_Word	cnt;

	/*
	 * Otherwise look for any .note sections.
	 */
	for (cnt = 1; cnt < shnum; cnt++) {
		Cache *		_cache = &cache[cnt];
		GElf_Shdr *	shdr = &_cache->c_shdr;

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
			(void) fflush(stderr);
			continue;
		}

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_NOTE), _cache->c_name);
		note_entry(_cache, (Word *)_cache->c_data->d_buf,
		/* LINTED */
		    (Word)_cache->c_data->d_size, file);
	}
}


#define	MAXCOUNT	500

static void
hash(Cache *cache, GElf_Word shnum, const char *name, const char *file,
    uint32_t flags)
{
	static int	count[MAXCOUNT];
	GElf_Word	cnt;
	ulong_t		ndx, bkts;
	char		number[MAXNDXSIZE];

	for (cnt = 1; cnt < shnum; cnt++) {
		uint_t		*hash, *chain;
		Elf_Data	*dsyms;
		Cache		*_cache = &cache[cnt];
		GElf_Shdr	*shdr = &_cache->c_shdr;
		char		*sname;

		if (shdr->sh_type != SHT_HASH)
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;

		/*
		 * Determine the hash table data and size.
		 */
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			(void) fflush(stderr);
			continue;
		}
		hash = (uint_t *)_cache->c_data->d_buf;
		bkts = *hash;
		chain = hash + 2 + bkts;
		hash += 2;

		/*
		 * Get the data buffer for the associated symbol table.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}
		dsyms = cache[shdr->sh_link].c_data;
		if (dsyms->d_buf == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, cache[shdr->sh_link].c_name);
			(void) fflush(stderr);
			continue;
		}

		sname = cache[shdr->sh_link].c_name;
		shdr = &cache[shdr->sh_link].c_shdr;
		/*
		 * Get the associated string table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, sname, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_ELF_SCN_HASH), _cache->c_name);
		dbg_print(MSG_INTL(MSG_ELF_HASH_INFO));

		/*
		 * Loop through the hash buckets, printing the appropriate
		 * symbols.
		 */
		for (ndx = 0; ndx < bkts; ndx++, hash++) {
			GElf_Sym	_sym;
			const char	*_str;
			GElf_Word	_ndx, _cnt;
			char		_number[MAXNDXSIZE];
			ulong_t		nbkt, nhash;

			if (*hash == 0) {
				count[0]++;
				continue;
			}

			/* LINTED */
			if (gelf_getsym(dsyms, (int)*hash, &_sym) == NULL) {
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_HSBADSYMNDX),
				    file, elf_errmsg(0));
				(void) fflush(stderr);
				_str = MSG_INTL(MSG_STR_UNKNOWN);
			} else {
				_str = string(_cache, (GElf_Word)*hash,
				    &cache[shdr->sh_link], file,
				    _sym.st_name);
			}

			(void) snprintf(number, MAXNDXSIZE,
			    /* LINTED */
			    MSG_ORIG(MSG_FMT_INTEGER), (int)ndx);
			(void) snprintf(_number, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX2), EC_XWORD(*hash));
			dbg_print(MSG_ORIG(MSG_FMT_HASH_INFO), number, _number,
			    demangle(_str, flags));

			/*
			 * Determine if this string is in the correct bucket.
			 */
			nhash = elf_hash(_str);
			nbkt = nhash % bkts;
			if (nbkt != ndx) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADHASH), file,
				    /* LINTED */
				    _cache->c_name, _str, (int)ndx, (int)nbkt);
				(void) fflush(stderr);
			}

			/*
			 * Determine if any other symbols are chained to this
			 * bucket.
			 */
			_ndx = chain[*hash];
			_cnt = 1;
			while (_ndx) {
				/* LINTED */
				if (gelf_getsym(dsyms, (int)_ndx,
				    &_sym) == NULL) {
					(void) fprintf(stderr,
						MSG_INTL(MSG_ERR_HSBADSYMNDX),
					    file, elf_errmsg(0));
					(void) fflush(stderr);
					_str = MSG_INTL(MSG_STR_UNKNOWN);
				} else
					_str = string(_cache, _ndx,
						&cache[shdr->sh_link], file,
						_sym.st_name);

				(void) snprintf(_number, MAXNDXSIZE,
				    MSG_ORIG(MSG_FMT_INDEX2), EC_XWORD(_ndx));
				dbg_print(MSG_ORIG(MSG_FMT_HASH_INFO),
				    MSG_ORIG(MSG_STR_EMPTY), _number,
				    demangle(_str, flags));
				_ndx = chain[_ndx];
				_cnt++;

				/*
				 * Determine if this string is in the correct
				 * bucket.
				 */
				nhash = elf_hash(_str);
				nbkt = nhash % bkts;
				if (nbkt != ndx) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ERR_BADHASH), file,
					    _cache->c_name, _str,
					    /* LINTED */
					    (int)ndx, (int)nbkt);
					(void) fflush(stderr);
				}
			}

			if (_cnt >= MAXCOUNT) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_HASH_OVERFLW), file,
				    _cache->c_name,
				    /* LINTED */
				    (int)ndx, _cnt);
				(void) fflush(stderr);
			} else
				count[_cnt]++;
		}
		break;
	}

	/*
	 * Print out the count information.
	 */
	bkts = cnt = 0;
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	for (ndx = 0; ndx < MAXCOUNT; ndx++) {
		GElf_Word	_cnt;

		if ((_cnt = count[ndx]) == 0)
			continue;

		(void) snprintf(number, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INTEGER),
		    /* LINTED */
		    (int)_cnt);
		/* LINTED */
		dbg_print(MSG_INTL(MSG_ELF_HASH_BKTS1), number, (int)ndx);
		bkts += _cnt;
		/* LINTED */
		cnt += (GElf_Word)(ndx * _cnt);
	}
	if (cnt) {
		(void) snprintf(number, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INTEGER),
		    /* LINTED */
		    (int)bkts);
		/* LINTED */
		dbg_print(MSG_INTL(MSG_ELF_HASH_BKTS2), number, (int)cnt);
	}
}


static void
group(Cache *cache, GElf_Word shnum, const char *name, const char *file,
    uint32_t flags)
{
	GElf_Word	cnt;

	for (cnt = 1; cnt < shnum; cnt++) {
		Cache		*_cache = &cache[cnt];
		GElf_Shdr	*shdr = &_cache->c_shdr;
		Elf_Data	*dsyms;
		GElf_Shdr	*symshdr;
		GElf_Sym	sym;
		const char	*symname;
		char		flgstrbuf[MSG_GRP_COMDAT_SIZE + 10];
		Word		*grpdata;
		size_t		_cnt;
		size_t		grpcnt;


		if (shdr->sh_type != SHT_GROUP)
			continue;
		if (name && strcmp(name, _cache->c_name))
			continue;
		dbg_print(MSG_INTL(MSG_GRP_LINE1), _cache->c_name);
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
				file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}

		if (shdr->sh_entsize != sizeof (Word)) {
			(void) fprintf(stderr, MSG_INTL(MSG_GRP_BADENTSZ),
				file, _cache->c_name,
				EC_XWORD(shdr->sh_entsize));
			(void) fflush(stderr);
		}
		symshdr = &(cache[shdr->sh_link].c_shdr);
		if ((symshdr->sh_type != SHT_SYMTAB) &&
		    (symshdr->sh_type != SHT_DYNSYM)) {
			(void) fprintf(stderr, MSG_INTL(MSG_GRP_NOTSYMTAB),
				file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}
		dsyms = cache[shdr->sh_link].c_data;
		if ((shdr->sh_info == SHN_UNDEF) || ((ulong_t)shdr->sh_info >
		    (symshdr->sh_size / symshdr->sh_entsize))) {
			(void) fprintf(stderr, MSG_INTL(MSG_GRP_BADSYMNDX),
				file, _cache->c_name, EC_XWORD(shdr->sh_info));
			(void) fflush(stderr);
			continue;
		}
		flgstrbuf[0] = '[';
		flgstrbuf[1] = '\0';
		if ((shdr->sh_size != 0) &&
		    (_cache->c_data) &&
		    ((grpdata = (Word *)_cache->c_data->d_buf) != 0)) {
			if (grpdata[0] & GRP_COMDAT) {
				(void) strcat(flgstrbuf,
					MSG_ORIG(MSG_GRP_COMDAT));
			}
			if ((grpdata[0] & ~GRP_COMDAT) != 0) {
				(void) snprintf(flgstrbuf + strlen(flgstrbuf),
				    (MSG_GRP_COMDAT_SIZE + 10),
				    MSG_ORIG(MSG_GRP_FMT1),
				    (uint_t)(grpdata[0] & ~GRP_COMDAT));
			}
		}
		(void) strcat(flgstrbuf, MSG_ORIG(MSG_GRP_CLOSBRKT));

		if (gelf_getsym(dsyms, shdr->sh_info, &sym) == NULL) {
			(void) fprintf(stderr,
				MSG_INTL(MSG_ERR_GRBADSYMNDX),
				file, elf_errmsg(0));
			(void) fflush(stderr);
		}
		symname = demangle(string(_cache, shdr->sh_link,
			&cache[symshdr->sh_link], file, sym.st_name),
			flags);
		dbg_print(MSG_INTL(MSG_GRP_LINE2));
		dbg_print(MSG_INTL(MSG_GRP_LINE3),
			flgstrbuf, symname);
		for (_cnt = 1, grpcnt = (shdr->sh_size / sizeof (Word));
		    _cnt < grpcnt; _cnt++) {
			char		index[MAXNDXSIZE];
			const char	*sname;

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(_cnt));
			if (grpdata[_cnt] >= shnum) {
				sname = MSG_INTL(MSG_GRP_INVALSCN);
			} else {
				sname = cache[grpdata[_cnt]].c_name;
			}
			(void) printf(MSG_ORIG(MSG_GRP_FMT2), index, sname,
				(uint_t)grpdata[_cnt]);
		}
	}
}


static void
got(Cache *cache, GElf_Word shnum, GElf_Word phnum, GElf_Ehdr *ehdr,
    const char *file)
{
	Cache		*gotcache = 0, *symtab = 0, *_cache;
	GElf_Addr	gotbgn, gotend;
	GElf_Shdr	*gotshdr;
	GElf_Word	cnt, gotents, gotndx;
	size_t		gentsize;
	Got_info	*gottable;
	char		*gotdata;
	GElf_Sym	gsym;
	GElf_Xword	gsymaddr;

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
	if (!gotcache)
		return;

	/*
	 * A got section within a relocatable object is suspicious.
	 */
	if (ehdr->e_type == ET_REL) {
		(void) fprintf(stderr, MSG_INTL(MSG_GOT_UNEXPECTED), file,
		    _cache->c_name);
		(void) fflush(stderr);
	}

	gotshdr = &gotcache->c_shdr;
	gotbgn = gotshdr->sh_addr;

	if (gotshdr->sh_size == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
		    file, gotcache->c_name);
		(void) fflush(stderr);
		return;
	}
	gotend = gotbgn + gotshdr->sh_size;

	/*
	 * Some architectures don't properly set the sh_entsize
	 * for the GOT table.  If it's not set we will default
	 * to a size of a pointer.
	 */
	if ((gentsize = gotshdr->sh_entsize) == 0) {
		if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
			gentsize = sizeof (GElf_Xword);
		else
			gentsize = sizeof (GElf_Word);
	}
	/* LINTED */
	gotents = (GElf_Word)(gotshdr->sh_size / gentsize);
	gotdata = gotcache->c_data->d_buf;

	if ((gottable = calloc(gotents, sizeof (Got_info))) == 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
			file, strerror(err));
		(void) fflush(stderr);
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
		GElf_Shdr	*shdr;
		GElf_Word	rtype;
		Elf_Data	*dsyms, *reldata;
		GElf_Rela	rela;
		ulong_t		rcount;
		int		ndx;
		char		*sname;

		_cache = &cache[cnt];
		shdr = &_cache->c_shdr;

		if ((symtab == 0) && (shdr->sh_type == SHT_DYNSYM)) {
			symtab = _cache;
			continue;
		}
		if (shdr->sh_type == SHT_SYMTAB) {
			symtab = _cache;
			continue;
		}

		rtype = shdr->sh_type;
		if ((rtype != SHT_RELA) && (rtype != SHT_REL))
			continue;

		/*
		 * Determine the relocation data and number.
		 */
		if ((shdr->sh_entsize == 0) || (shdr->sh_size == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, _cache->c_name);
			(void) fflush(stderr);
			continue;
		}
		rcount = shdr->sh_size / shdr->sh_entsize;

		reldata = _cache->c_data;

		/*
		 * Get the data buffer for the associated symbol table.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
				file, _cache->c_name, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}
		dsyms = cache[shdr->sh_link].c_data;
		if (dsyms->d_buf == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSZ),
			    file, cache[shdr->sh_link].c_name);
			(void) fflush(stderr);
			continue;
		}

		sname = cache[shdr->sh_link].c_name;
		shdr = &cache[shdr->sh_link].c_shdr;
		/*
		 * Get the associated string table section.
		 */
		if ((shdr->sh_link == 0) || (shdr->sh_link >= shnum)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADSHLINK),
			    file, sname, EC_XWORD(shdr->sh_link));
			(void) fflush(stderr);
			continue;
		}

		/* LINTED */
		for (ndx = 0; ndx < rcount; ++ndx) {
			GElf_Sym 	_sym;
			GElf_Word	sndx;
			GElf_Addr	offset;
			Got_info	*gip;
			void		*relret;

			if (rtype == SHT_RELA) {
				relret = (void *)gelf_getrela(reldata, ndx,
				    &rela);
			} else {
				relret = (void *)gelf_getrel(reldata, ndx,
				    (GElf_Rel *)&rela);
			}
			if (relret == NULL) {
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADREL),
				    file, _cache->c_name, elf_errmsg(0));
				(void) fflush(stderr);
				break;
			}

			offset = rela.r_offset;
			/* LINTED */
			sndx = (GElf_Word)GELF_R_SYM(rela.r_info);

			/*
			 * Only pay attention to relocations against the GOT.
			 */
			if ((offset < gotbgn) || (offset > gotend))
				continue;

			/* LINTED */
			gotndx = (GElf_Word)((offset - gotbgn) /
			    gotshdr->sh_entsize);
			gip = &gottable[gotndx];
			if (gip->g_rshtype != 0) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_GOT_MULTIPLE), file,
				    /* LINTED */
				    EC_WORD(gotndx), EC_XWORD(offset));
				(void) fflush(stderr);
				continue;
			}

			/* LINTED */
			if (gelf_getsym(dsyms, sndx, &_sym) == NULL) {
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_RELBADSYMNDX),
				    file, elf_errmsg(0));
				(void) fflush(stderr);
				gip->g_symname = MSG_INTL(MSG_STR_UNKNOWN);
			} else {
				gip->g_symname = string(_cache, sndx,
				    &cache[shdr->sh_link], file, _sym.st_name);
			}
			gip->g_rshtype = rtype;
			gip->g_rela = rela;
		}
	}

	if (symlookup(MSG_ORIG(MSG_GOT_SYM), cache, shnum, &gsym, symtab, file))
		gsymaddr = gsym.st_value;
	else
		gsymaddr = gotbgn;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_ELF_SCN_GOT), gotcache->c_name, gotents);
	Gelf_got_title(ehdr->e_ident[EI_CLASS]);

	for (gotndx = 0; gotndx < gotents; gotndx++) {
		Got_info	*gip;
		Sword		gindex;
		GElf_Addr	gaddr;
		GElf_Xword	gotentry;

		gip = &gottable[gotndx];

		gaddr = gotbgn + (gotndx * gentsize);
		/* LINTED */
		gindex = (Sword)((gaddr - gsymaddr) / gentsize);

		if (gentsize == sizeof (GElf_Word))
			/* LINTED */
			gotentry = (GElf_Xword)(*((GElf_Word *)(gotdata) +
			    gotndx));
		else
			/* LINTED */
			gotentry = *((GElf_Xword *)(gotdata) + gotndx);

		Gelf_got_entry(ehdr, gindex, gaddr, gotentry, gip->g_rshtype,
		    &gip->g_rela, gip->g_symname);
	}

	free(gottable);
}

void
checksum(Elf *elf)
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_STR_CHECKSUM), gelf_checksum(elf));
}

static void
regular(const char *file, Elf *elf, uint32_t flags, char *Nname, int wfd)
{
	Elf_Scn		*scn;
	GElf_Ehdr	ehdr;
	Elf_Data	*data;
	uint_t		cnt;
	GElf_Word	shnum, phnum;
	size_t		shstrndx, _shnum, _phnum;
	GElf_Shdr	nameshdr;
	GElf_Shdr	shdr0;
	GElf_Shdr	*_shdr0;
	char		*names = 0;
	Cache		*cache, *_cache;
	Cache		*versymcache;

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETEHDR));
		return;
	}

	if (elf_getshnum(elf, &_shnum) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHNUM));
		return;
	}
	/* LINTED */
	shnum = (GElf_Word)_shnum;

	if (elf_getshstrndx(elf, &shstrndx) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHSTRNDX));
		return;
	}

	if (elf_getphnum(elf, &_phnum) == 0) {
		failure(file, MSG_ORIG(MSG_ELF_GETPHNUM));
		return;
	}
	/* LINTED */
	phnum = (GElf_Word)_phnum;

	if ((scn = elf_getscn(elf, 0)) != NULL) {
		if ((_shdr0 = gelf_getshdr(scn, &shdr0)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN), 0);
			(void) fflush(stderr);
			return;
		}
	} else
		_shdr0 = 0;

	/*
	 * Print the elf header.
	 */
	if (flags & FLG_EHDR)
		Gelf_elf_header(&ehdr, _shdr0);

	/*
	 * Print the program headers.
	 */
	if ((flags & FLG_PHDR) && phnum != 0) {
		GElf_Phdr phdr;

		for (cnt = 0; cnt < phnum; cnt++) {
			if (gelf_getphdr(elf, cnt, &phdr) == NULL) {
				failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
				return;
			}

			dbg_print(MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(MSG_INTL(MSG_ELF_PHDR), cnt);
			Gelf_phdr_entry(ehdr.e_machine, &phdr);
		}
	}


	/*
	 * Return now if there are no section, if there's just one section to
	 * act as an extension of the ELF header, or if on section information
	 * was requested.
	 */
	if ((shnum <= 1) || (flags && (flags & ~(FLG_EHDR | FLG_PHDR)) == 0)) {
		if ((ehdr.e_type == ET_CORE) && (flags & FLG_NOTE))
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
		(void) fflush(stderr);
	} else if ((data = elf_getdata(scn, NULL)) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETDATA));
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_DATA),
		    EC_XWORD(shstrndx));
		(void) fflush(stderr);
	} else if (gelf_getshdr(scn, &nameshdr) == NULL) {
		failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN),
		    /* LINTED */
		    (int)elf_ndxscn(scn));
		(void) fflush(stderr);
	} else if ((names = data->d_buf) == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_SHSTRNULL), file);
		(void) fflush(stderr);
	}

	/*
	 * Fill in the cache descriptor with information for each section.
	 */
	if ((cache = malloc(shnum * sizeof (Cache))) == 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    file, strerror(err));
		(void) fflush(stderr);
		return;
	}

	*cache = _cache_init;
	_cache = cache;
	_cache++;

	for (cnt = 1, scn = NULL; scn = elf_nextscn(elf, scn);
	    cnt++, _cache++) {
		if (gelf_getshdr(scn, &_cache->c_shdr) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN),
			    /* LINTED */
			    (int)elf_ndxscn(scn));
			(void) fflush(stderr);
		}

		if (names && _cache->c_shdr.sh_name &&
		    /* LINTED */
		    (nameshdr.sh_size > _cache->c_shdr.sh_name))
			_cache->c_name = names + _cache->c_shdr.sh_name;
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
			    (nameshdr.sh_size <= _cache->c_shdr.sh_name)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADSHNAME), file,
				    _cache->c_name,
				    EC_XWORD(_cache->c_shdr.sh_name));
				(void) fflush(stderr);
			}

			if ((_cache->c_name =
			    malloc(strlen(scnndxnm) + 1)) == 0) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
				    file, strerror(err));
				(void) fflush(stderr);
				return;
			}
			(void) strcpy(_cache->c_name, scnndxnm);
		}

		if ((_cache->c_data = elf_getdata(scn, NULL)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETDATA));
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCNDATA),
			    /* LINTED */
			    (int)elf_ndxscn(scn));
			(void) fflush(stderr);
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
		sections(file, cache, shnum, phnum, &ehdr, Nname);

	if (flags & FLG_INTERP)
		interp(file, cache, shnum, phnum, &ehdr, elf);

	versymcache = versions(cache, shnum, file, flags);

	if (flags & FLG_SYMBOLS)
		symbols(cache, shnum, phnum, &ehdr, Nname, versymcache, file);

	if (flags & FLG_HASH)
		hash(cache, shnum, Nname, file, flags);

	if (flags & FLG_GOT)
		got(cache, shnum, phnum, &ehdr, file);

	if (flags & FLG_GROUP)
		group(cache, shnum, Nname, file, flags);

	if (flags & FLG_SYMINFO)
		syminfo(cache, shnum, file);

	if (flags & FLG_RELOC)
		reloc(cache, shnum, phnum, &ehdr, Nname, file, flags);

	if (flags & FLG_DYNAMIC)
		dynamic(cache, shnum, &ehdr, file);

	if (flags & FLG_NOTE)
		note(cache, shnum, Nname, file);

	if (flags & FLG_MOVE)
		move(cache, shnum, Nname, file, flags);

	if (flags & FLG_CHECKSUM)
		checksum(elf);

	if (flags & FLG_CAP)
		cap(file, cache, shnum, phnum, &ehdr, elf);

	if (flags & FLG_UNWIND)
		unwind(cache, shnum, phnum, &ehdr, Nname, file, elf);

	free(cache);
}

static void
archive(const char *file, int fd, Elf *elf, uint32_t flags, char *Nname,
    int wfd)
{
	Elf_Cmd		cmd = ELF_C_READ;
	Elf_Arhdr	*arhdr;
	Elf		*_elf = 0;
	size_t		ptr;
	Elf_Arsym	*arsym = 0;

	/*
	 * Determine if the archive sysmbol table itself is required.
	 */
	if ((flags & FLG_SYMBOLS) && ((Nname == NULL) ||
	    (strcmp(Nname, MSG_ORIG(MSG_ELF_ARSYM)) == 0))) {
		/*
		 * Get the archive symbol table.
		 */
		if (((arsym = elf_getarsym(elf, &ptr)) == 0) && elf_errno()) {
			/*
			 * The arsym could be 0 even though there was no error.
			 * Print the error message only when there was
			 * real error from elf_getarsym().
			 */
			failure(file, MSG_ORIG(MSG_ELF_GETARSYM));
			return;
		}
	}

	/*
	 * Print the archive symbol table only when the archive symbol
	 * table exists and it was requested to print.
	 */
	if (arsym) {
		size_t		cnt;
		char		index[MAXNDXSIZE];
		size_t		offset = 0, _offset = 0;

		/*
		 * Print out all the symbol entries.
		 */
		dbg_print(MSG_INTL(MSG_ARCHIVE_SYMTAB));
		dbg_print(MSG_INTL(MSG_ARCHIVE_FIELDS));

		for (cnt = 0; cnt < ptr; cnt++, arsym++) {
			/*
			 * For each object obtain an elf descriptor so that we
			 * can establish the members name.  Note, we have had
			 * archives where the archive header has not been
			 * obtainable so be lenient with errors.
			 */
			if ((offset == 0) || ((arsym->as_off != 0) &&
			    (arsym->as_off != _offset))) {

				if (_elf)
					(void) elf_end(_elf);

				if (elf_rand(elf, arsym->as_off) !=
				    arsym->as_off) {
					failure(file, MSG_ORIG(MSG_ELF_RAND));
					arhdr = 0;
				} else if ((_elf = elf_begin(fd,
				    ELF_C_READ, elf)) == 0) {
					failure(file, MSG_ORIG(MSG_ELF_BEGIN));
					arhdr = 0;
				} else if ((arhdr = elf_getarhdr(_elf)) == 0) {
					failure(file,
					    MSG_ORIG(MSG_ELF_GETARHDR));
					arhdr = 0;
				}

				_offset = arsym->as_off;
				if (offset == 0)
					offset = _offset;
			}

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(cnt));
			if (arsym->as_off)
				dbg_print(MSG_ORIG(MSG_FMT_ARSYM1), index,
				    /* LINTED */
				    (int)arsym->as_off, arhdr ? arhdr->ar_name :
				    MSG_INTL(MSG_STR_UNKNOWN), (arsym->as_name ?
				    demangle(arsym->as_name, flags) :
				    MSG_INTL(MSG_STR_NULL)));
			else
				dbg_print(MSG_ORIG(MSG_FMT_ARSYM2), index,
				    /* LINTED */
				    (int)arsym->as_off);
		}

		if (_elf)
			(void) elf_end(_elf);

		/*
		 * If we only need the archive symbol table return.
		 */
		if ((flags & FLG_SYMBOLS) && Nname &&
		    (strcmp(Nname, MSG_ORIG(MSG_ELF_ARSYM)) == 0))
			return;

		/*
		 * Reset elf descriptor in preparation for processing each
		 * member.
		 */
		if (offset)
			(void) elf_rand(elf, offset);
	}

	/*
	 * Process each object within the archive.
	 */
	while ((_elf = elf_begin(fd, cmd, elf)) != NULL) {
		char	name[MAXPATHLEN];

		if ((arhdr = elf_getarhdr(_elf)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETARHDR));
			return;
		}
		if (*arhdr->ar_name != '/') {
			(void) snprintf(name, MAXPATHLEN,
			    MSG_ORIG(MSG_FMT_ARNAME), file, arhdr->ar_name);
			dbg_print(MSG_ORIG(MSG_FMT_NLSTR), name);

			switch (elf_kind(_elf)) {
			case ELF_K_AR:
				archive(name, fd, _elf, flags, Nname, wfd);
				break;
			case ELF_K_ELF:
				regular(name, _elf, flags, Nname, wfd);
				break;
			default:
				(void) fprintf(stderr,
					MSG_INTL(MSG_ERR_BADFILE), name);
				(void) fflush(stderr);
				break;
			}
		}

		cmd = elf_next(_elf);
		(void) elf_end(_elf);
	}
}

int
main(int argc, char **argv, char **envp)
{
	Elf		*elf;
	int		var, fd, wfd = 0;
	char		*Nname = NULL, *wname = 0;
	uint32_t	flags = 0, dbg_flags = 0;

	/*
	 * If we're on a 64-bit kernel, try to exec a full 64-bit version of
	 * the binary.  If successful, conv_check_native() won't return.
	 */
	conv_check_native(argv, envp);

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	(void) setvbuf(stdout, NULL, _IOLBF, 0);
	(void) setvbuf(stderr, NULL, _IOLBF, 0);

	opterr = 0;
	while ((var = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != EOF) {
		switch (var) {
		case 'C':
			flags |= FLG_DEMANGLE;
			break;
		case 'c':
			flags |= FLG_SHDR;
			break;
		case 'd':
			flags |= FLG_DYNAMIC;
			break;
		case 'e':
			flags |= FLG_EHDR;
			break;
		case 'G':
			flags |= FLG_GOT;
			break;
		case 'g':
			flags |= FLG_GROUP;
			break;
		case 'H':
			flags |= FLG_CAP;
			break;
		case 'h':
			flags |= FLG_HASH;
			break;
		case 'i':
			flags |= FLG_INTERP;
			break;
		case 'k':
			flags |= FLG_CHECKSUM;
			break;
		case 'l':
			flags |= FLG_LONGNAME;
			break;
		case 'm':
			flags |= FLG_MOVE;
			break;
		case 'N':
			Nname = optarg;
			break;
		case 'n':
			flags |= FLG_NOTE;
			break;
		case 'p':
			flags |= FLG_PHDR;
			break;
		case 'r':
			flags |= FLG_RELOC;
			break;
		case 's':
			flags |= FLG_SYMBOLS;
			break;
		case 'u':
			flags |= FLG_UNWIND;
			break;
		case 'v':
			flags |= FLG_VERSIONS;
			break;
		case 'w':
			wname = optarg;
			break;
		case 'y':
			flags |= FLG_SYMINFO;
			break;
		case '?':
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
			    basename(argv[0]));
			detail_usage();
			return (1);
		default:
			break;
		}
	}

	/*
	 * Validate any arguments.
	 */
	if (flags == 0) {
		if (!wname && !Nname) {
			flags = FLG_EVERYTHING;
		} else if (!wname || !Nname) {
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
			    basename(argv[0]));
			return (1);
		}
	}

	if ((var = argc - optind) == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
		    basename(argv[0]));
		return (1);
	}

	/*
	 * If the -C option is used by itself, report an error since the option
	 * has no use without other symbol name generating options.
	 *
	 * If the -l option is used by itself, report an error.
	 */
	if ((flags == FLG_DEMANGLE) || (flags == FLG_LONGNAME) ||
	    (flags == (FLG_DEMANGLE | FLG_LONGNAME))) {
		if (flags & FLG_DEMANGLE)
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DEMANGLE));
		if (flags & FLG_LONGNAME)
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_LONGNAME));
		return (1);
	}

	/*
	 * If the -l/-C option is specified, set up the liblddbg.so.
	 */
	if (flags & FLG_LONGNAME)
		dbg_flags = DBG_LONG;
	if (flags & FLG_DEMANGLE)
		dbg_flags |= DBG_DEMANGLE;
	if (dbg_flags)
		Dbg_set(dbg_flags);

	/*
	 * If the -w option has indicated an output file open it.  It's
	 * arguable whether this option has much use when multiple files are
	 * being processed.
	 */
	if (wname) {
		if ((wfd = open(wname, (O_RDWR | O_CREAT | O_TRUNC),
		    0666)) < 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN),
			    wname, strerror(err));
			(void) fflush(stderr);
			wfd = 0;
		}
	}

	/*
	 * Open the input file and initialize the elf interface.
	 */
	for (; optind < argc; optind++) {
		const char	*file = argv[optind];

		if ((fd = open(argv[optind], O_RDONLY)) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN),
			    file, strerror(err));
			(void) fflush(stderr);
			continue;
		}
		(void) elf_version(EV_CURRENT);
		if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_BEGIN));
			(void) close(fd);
			continue;
		}

		if (var > 1)
			dbg_print(MSG_ORIG(MSG_FMT_NLSTRNL), file);

		switch (elf_kind(elf)) {
		case ELF_K_AR:
			archive(file, fd, elf, flags, Nname, wfd);
			break;
		case ELF_K_ELF:
			regular(file, elf, flags, Nname, wfd);
			break;
		default:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADFILE), file);
			(void) fflush(stderr);
			break;
		}

		(void) close(fd);
		(void) elf_end(elf);
	}

	if (wfd)
		(void) close(wfd);
	return (0);
}
