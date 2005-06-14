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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>
#include <libelf.h>
#include <link.h>
#include <sys/elf_M32.h>
#include <sys/elf_386.h>
#include <sys/elf_SPARC.h>
#include <sys/machelf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include "sgs.h"
#include "conv.h"
#include "dump.h"


#define	OPTSTR	"agcd:fhn:oprstvCLT:V?"		/* option string for getopt() */

const char *UNKNOWN = "<unknown>";

static SCNTAB *p_symtab, *p_head_scns, *p_dynsym;

static int
	x_flag = 0,	/* option requires section header table */
	z_flag = 0,	/* process files within an archive */
	rn_flag = 0;	/* dump named relocation information */

static int
	/* flags: ?_flag corresponds to ? option */
	a_flag = 0,	/* dump archive header of each member of archive */
	g_flag = 0,	/* dump archive symbol table */
	c_flag = 0,	/* dump the string table */
	d_flag = 0,	/* dump range of sections */
	f_flag = 0,	/* dump each file header */
	h_flag = 0,	/* dump section headers */
	n_flag = 0,	/* dump named section */
	o_flag = 0,	/* dump each program execution header */
	r_flag = 0,	/* dump relocation information */
	s_flag = 0,	/* dump section contents */
	t_flag = 0,	/* dump symbol table entries */
	C_flag = 0,	/* dump decoded C++ symbol names */
	L_flag = 0,	/* dump dynamic linking information */
	T_flag = 0,	/* dump symbol table range */
	V_flag = 0;	/* dump version information */

int	p_flag = 0,	/* suppress printing of headings */
	v_flag = 0;	/* print information in verbose form */

static int
	d_low = 0,	/* range for use with -d */
	d_hi = 0,
	d_num = 0;

static int
	T_low = 0,	/* range for use with -T */
	T_hi = 0,
	T_num = 0;

static char *name = NULL; /* for use with -n option */
char *prog_name;
static int errflag = 0;

static struct stab_list_s {
	struct stab_list_s *next;
	char *strings;
	size_t size;
} *StringTableList = (void *)0;

extern void ar_sym_read();
extern void dump_exec_header();


/*
 * Get the section descriptor and set the size of the
 * data returned.  Data is byte-order converted.
 */
void *
get_scndata(Elf_Scn *fd_scn, size_t *size)
{
	Elf_Data *p_data;

	p_data = 0;
	if ((p_data = elf_getdata(fd_scn, p_data)) == 0 ||
	    p_data->d_size == 0) {
		return (NULL);
	}
	*size = p_data->d_size;
	return (p_data->d_buf);
}

/*
 * Get the section descriptor and set the size of the
 * data returned.  Data is raw (i.e., not byte-order converted).
 */
static void *
get_rawscn(Elf_Scn *fd_scn, size_t *size)
{
	Elf_Data *p_data;

	p_data = 0;
	if ((p_data = elf_rawdata(fd_scn, p_data)) == 0 ||
	    p_data->d_size == 0) {
		return (NULL);
	}

	*size = p_data->d_size;
	return (p_data->d_buf);
}

/*
 * Print out a usage message in short form when program is invoked
 * with insufficient or no arguments, and in long form when given
 * either a ? or an invalid option.
 */
static void
usage()
{
	(void) fprintf(stderr,
	"Usage: %s [-%s] file(s) ...\n", prog_name, OPTSTR);
	if (errflag) {
		(void) fprintf(stderr,
		"\t\t[-a dump archive header of each member of archive]\n\
		[-g dump archive global symbol table]\n\
		[-c dump the string table]\n\
		[-d dump range of sections]\n\
		[-f dump each file header]\n\
		[-h dump section headers]\n\
		[-n dump named section]\n\
		[-o dump each program execution header]\n\
		[-p suppress printing of headings]\n\
		[-r dump relocation information]\n\
		[-s dump section contents]\n\
		[-t dump symbol table entries]\n\
		[-v print information in verbose form]\n\
		[-C dump decoded C++ symbol names]\n\
		[-L dump the .dynamic structure]\n\
		[-T dump symbol table range]\n\
		[-V dump version information]\n");
	}
}

/*
 * Set a range.  Input is a character string, a lower
 * bound and an upper bound.  This function converts
 * a character string into its correct integer values,
 * setting the first value as the lower bound, and
 * the second value as the upper bound.  If more values
 * are given they are ignored with a warning.
 */
static void
set_range(char *s, int  *low, int  *high)
{
	char *w;
	char *lasts;

	while ((w = strtok_r(s, ",", &lasts)) != NULL) {
		if (!(*low))
			/* LINTED */
			*low = (int)atol(w);
		else
			if (!(*high))
				/* LINTED */
				*high = (int)atol(w);
			else {
				(void) fprintf(stderr,
					"%s: too many arguments - %s ignored\n",
					prog_name, w);
				return;
			}
		s = NULL;
	} /* end while */
}


/*
 * Print static shared library information.
 */
static void
print_static(SCNTAB *l_scns, char *filename)
{
	size_t section_size;
	unsigned char *strtab;
	unsigned char *path, buf[1024];
	unsigned long *temp;
	unsigned long total, topath;

	(void) printf("\n  **** STATIC SHARED LIBRARY INFORMATION ****\n");
	(void) printf("\n%s:\n", filename);
	(void) printf("\t");
	section_size  = 0;
	if ((strtab = (unsigned char *)
	    get_scndata(l_scns->p_sd, &section_size)) == NULL) {
		return;
	}

	while (section_size != 0) {
		/* LINTED */
		temp = (unsigned long *)strtab;
		total = temp[0];
		topath = temp[1];
		path = strtab + (topath*sizeof (long));
		(void) strncpy((char *)buf, (char *)path,
			(total - topath)*sizeof (long));
		(void) fprintf(stdout, "%s\n", buf);
		strtab += total*sizeof (long);
		section_size -= (total*sizeof (long));
	}
}

/*
 * Print raw data in hexidecimal.  Input is the section data to
 * be printed out and the size of the data.  Output is relative
 * to a table lookup in dumpmap.h.
 */
static void
print_rawdata(unsigned char *p_sec, size_t size)
{
	size_t   j;
	size_t   count;

	count = 1;

	(void) printf("\t");
	for (j = size/sizeof (short); j != 0; --j, ++count) {
		(void) printf("%.2x %.2x ", p_sec[0], p_sec[1]);
		p_sec += 2;
		if (count == 12) {
			(void) printf("\n\t");
			count = 0;
		}
	}

	/*
	 * take care of last byte if odd byte section
	 */
	if ((size & 0x1L) == 1L)
		(void) printf("%.2x", *p_sec);
	(void) printf("\n");
}



/*
 * Print relocation data of type SHT_RELA
 * If d_flag, print data corresponding only to
 * the section or range of sections specified.
 * If n_flag, print data corresponding only to
 * the named section.
 */
static void
print_rela(Elf *elf_file, SCNTAB *p_scns, Elf_Data *rdata, Elf_Data *sym_data,
	GElf_Ehdr * p_ehdr, size_t reloc_size, size_t sym_size, char *filename,
	SCNTAB *reloc_symtab)
{
	GElf_Rela rela;
	GElf_Sym sym;
	size_t no_entries;
	size_t rel_entsize;
	size_t no_syms;
	int type, symid;
	static int n_title = 0;
	int ndx = 0;
	char *sym_name;
	int adj = 0;

	if (gelf_getclass(elf_file) == ELFCLASS64)
		adj = 4;

	rel_entsize = p_scns->p_shdr.sh_entsize;
	if ((rel_entsize == 0) ||
	    (rel_entsize > p_scns->p_shdr.sh_size)) {
		rel_entsize = gelf_fsize(elf_file, ELF_T_RELA, 1,
		    EV_CURRENT);
	}
	no_entries = reloc_size / rel_entsize;

	no_syms = sym_size / gelf_fsize(elf_file, ELF_T_SYM, 1, EV_CURRENT);
	while (no_entries--) {
		(void) gelf_getrela(rdata, ndx, &rela);
		/* LINTED */
		type = (int)GELF_R_TYPE(rela.r_info);
		/* LINTED */
		symid = (int)GELF_R_SYM(rela.r_info);
		/* LINTED */
		if ((symid > (no_syms - 1)) || (symid < 0)) {
			(void) fprintf(stderr, "%s: %s: invalid symbol table "
			    "offset - %d - in %s\n", prog_name, filename,
			    symid, p_scns->scn_name);
			ndx++;
			continue;
		}
		(void) gelf_getsym(sym_data, symid, &sym);
		sym_name = (char *)elf_strptr(elf_file,
			reloc_symtab->p_shdr.sh_link, sym.st_name);
		if (sym_name == NULL)
			sym_name = (char *)UNKNOWN;
		if (r_flag && rn_flag) {
			if (strcmp(name, p_scns->scn_name) != 0) {
				ndx++;
				continue;
			}
			if (!n_title) {
				(void) printf("\n%s:\n", p_scns->scn_name);
				(void) printf("%-*s%-*s%-*s%s\n\n",
				    12 + adj, "Offset", 22, "Symndx",
				    16, "Type", "Addend");
				n_title = 1;
			}
		}
		if (d_flag) {
			if (!d_hi)
				d_hi = d_low;
			if ((symid < d_low) || (symid > d_hi)) {
				ndx++;
				continue;
			}
		}

		(void) printf("%-#*llx", 12 + adj, EC_XWORD(rela.r_offset));
		if (!v_flag) {
			(void) printf("%-22d%-18d", symid, type);
		} else {
			if (strlen(sym_name)) {
				size_t len = strlen(sym_name) + 1;
				char tmpstr[10];
				if (len > 22) {
					(void) sprintf(tmpstr, "%%-%ds",
						/* LINTED */
						(int)len);
					(void) printf(tmpstr, sym_name);
				} else
					(void) printf("%-22s", sym_name);
			} else
				(void) printf("%-22d", symid);
			print_reloc_type(p_ehdr->e_machine, type);
		}
		(void) printf("%lld\n", EC_SXWORD(rela.r_addend));
		ndx++;
	}
}

/*
 * Print relocation data of type SHT_REL.
 * If d_flag, print data corresponding only to
 * the section or range of sections specified.
 * If n_flag, print data corresponding only to
 * the named section.
 */
static void
print_rel(Elf *elf_file, SCNTAB *p_scns, Elf_Data *rdata, Elf_Data *sym_data,
	GElf_Ehdr *p_ehdr, size_t reloc_size, size_t sym_size, char *filename,
	SCNTAB *reloc_symtab)
{
	GElf_Rel rel;
	GElf_Sym sym;
	size_t no_entries;
	size_t rel_entsize;
	int type, symid;
	size_t no_syms;
	static int n_title = 0;
	int ndx = 0;
	char *sym_name;
	int adj = 0;

	if (gelf_getclass(elf_file) == ELFCLASS64)
		adj = 4;

	rel_entsize = p_scns->p_shdr.sh_entsize;
	if ((rel_entsize == 0) ||
	    (rel_entsize > p_scns->p_shdr.sh_size)) {
		rel_entsize = gelf_fsize(elf_file, ELF_T_REL, 1,
		    EV_CURRENT);
	}
	no_entries = reloc_size / rel_entsize;

	no_syms = sym_size / gelf_fsize(elf_file, ELF_T_SYM, 1, EV_CURRENT);
	while (no_entries--) {
		(void) gelf_getrel(rdata, ndx, &rel);
		/* LINTED */
		type = (int)GELF_R_TYPE(rel.r_info);
		/* LINTED */
		symid = (int)GELF_R_SYM(rel.r_info);
		/* LINTED */
		if ((symid > (no_syms - 1)) || (symid < 0)) {
			(void) fprintf(stderr, "%s: %s: invalid symbol table "
			    "offset - %d - in %s\n", prog_name, filename,
			    symid, p_scns->scn_name);
			ndx++;
			continue;
		}
		(void) gelf_getsym(sym_data, symid, &sym);
		sym_name = (char *)elf_strptr(elf_file,
			reloc_symtab->p_shdr.sh_link, sym.st_name);
		if (sym_name == NULL)
			sym_name = (char *)UNKNOWN;
		if (r_flag && rn_flag) {
			if (strcmp(name, p_scns->scn_name) != 0) {
				ndx++;
				continue;
			}
			if (!n_title) {
				(void) printf("\n%s:\n", p_scns->scn_name);
				(void) printf("%-*s%-*s%s\n\n",
				    12 + adj, "Offset", 20, "Symndx", "Type");
				n_title = 1;
			}
		}
		if (d_flag) {
			if (!d_hi)
				d_hi = d_low;
			if ((symid < d_low) || (symid > d_hi)) {
				ndx++;
				continue;
			}
		}

		(void) printf("%-#*llx", 12 + adj, EC_ADDR(rel.r_offset));
		if (!v_flag) {
			(void) printf("%-20d%-18d", symid, type);
		} else {
			if (strlen(sym_name))
				(void) printf("%-20s", sym_name);
			else
				(void) printf("%-20d", sym.st_name);

			print_reloc_type(p_ehdr->e_machine, type);
		}
		(void) printf("\n");
		ndx++;
	}
}

/* demangle C++ names */
static char *format = "%s\t[%s]";
static char *
demangled_name(char *s)
{
	char *dn;
	static char *buf;

	dn = sgs_demangle(s);

	/*
	 * If not demangled, just return the symbol name
	 */
	if (strcmp(s, dn) == 0)
		return (s);

	/*
	 * Demangled. Format it
	 */
	if (buf != NULL)
		free(buf);

	buf = malloc(strlen(dn) + 1 + 1 + strlen(s) + 1 + 1);
	if (buf == NULL)
		return (s);

	(void) sprintf(buf, format, dn, s);
	return (buf);
}

/*
 * Print the symbol table.  Input is an ELF file descriptor, a
 * pointer to the symbol table SCNTAB structure,
 * the number of symbols, a range of symbols to print,
 * an index which is the number of the
 * section in the file, and the filename.  The number of sections,
 * the range, and the index are set in
 * dump_symbol_table, depending on whether -n or -T were set.
 */
static void
print_symtab(Elf *elf_file, SCNTAB *p_symtab, Elf_Data *sym_data,
	long range, int index)
{
	GElf_Sym sym;
	int adj = 0;		/* field adjustment for elf64 */
	Elf32_Word	*symshndx = 0;
	unsigned int	nosymshndx = 0;

	if (gelf_getclass(elf_file) == ELFCLASS64)
		adj = 4;

	while (range > 0) {
		char		*sym_name = (char *)0;
		int		type, bind;
		int		specsec;
		unsigned int	shndx;

		(void) gelf_getsym(sym_data, index, &sym);
		type = (int)GELF_ST_TYPE(sym.st_info);
		bind = (int)GELF_ST_BIND(sym.st_info);

		if ((sym.st_shndx == SHN_XINDEX) &&
		    (symshndx == 0) && (nosymshndx == 0)) {
			Elf_Scn		*_scn;
			GElf_Shdr	_shdr;
			size_t		symscnndx;

			symscnndx = elf_ndxscn(p_symtab->p_sd);
			_scn = 0;
			while ((_scn = elf_nextscn(elf_file, _scn)) != 0) {
				if (gelf_getshdr(_scn, &_shdr) == 0)
					break;
				if ((_shdr.sh_type == SHT_SYMTAB_SHNDX) &&
				    /* LINTED */
				    (_shdr.sh_link == (GElf_Word)symscnndx)) {
					Elf_Data	*_data;

					if ((_data = elf_getdata(_scn, 0)) == 0)
						continue;

					symshndx = (Elf32_Word *)_data->d_buf;
					nosymshndx = 0;
					break;
				}
			}
			nosymshndx = 1;
		}

		if ((symshndx) && (sym.st_shndx == SHN_XINDEX)) {
			shndx = symshndx[index];
			specsec = 0;
		} else {
			shndx = sym.st_shndx;
			if ((sym.st_shndx == SHN_UNDEF) ||
			    (sym.st_shndx >= SHN_LORESERVE))
				specsec = 1;
			else
				specsec = 0;
		}


		(void) printf("[%d]\t ", index++);

		if (v_flag && (type == STT_SPARC_REGISTER)) {
			/*
			 *  The strings "REG_G1" through "REG_G7" are intended
			 *  to be consistent with output from elfdump(1).
			 */
			switch (sym.st_value) {
			case STO_SPARC_REGISTER_G1:
				(void) printf("%-*s", 12 + adj, "REG_G1");
				break;
			case STO_SPARC_REGISTER_G2:
				(void) printf("%-*s", 12 + adj, "REG_G2");
				break;
			case STO_SPARC_REGISTER_G3:
				(void) printf("%-*s", 12 + adj, "REG_G3");
				break;
			case STO_SPARC_REGISTER_G4:
				(void) printf("%-*s", 12 + adj, "REG_G4");
				break;
			case STO_SPARC_REGISTER_G5:
				(void) printf("%-*s", 12 + adj, "REG_G5");
				break;
			case STO_SPARC_REGISTER_G6:
				(void) printf("%-*s", 12 + adj, "REG_G6");
				break;
			case STO_SPARC_REGISTER_G7:
				(void) printf("%-*s", 12 + adj, "REG_G7");
				break;
			default:
				(void) printf("0x%-*llx", 10 + adj,
				    EC_ADDR(sym.st_value));
			}
		} else
			(void) printf("0x%-*llx", 10 + adj,
			    EC_ADDR(sym.st_value));

		(void) printf("%-*lld", 9 + adj, EC_XWORD(sym.st_size));

		if (!v_flag) {
			(void) printf("%d\t\t%d\t%d\t%#x\t",
			    type, bind, (int)sym.st_other, (int)shndx);
		} else {
			switch (type) {
			case STT_NOTYPE:
				(void) printf("%s\t", "NOTY");
				break;
			case STT_OBJECT:
				(void) printf("%s\t", "OBJT");
				break;
			case STT_FUNC:
				(void) printf("%s\t", "FUNC");
				break;
			case STT_SECTION:
				(void) printf("%s\t", "SECT");
				break;
			case STT_FILE:
				(void) printf("%s\t", "FILE");
				break;
			case STT_SPARC_REGISTER:
				(void) printf("%s\t", "REGI");
				break;
			case STT_COMMON:
				(void) printf("%s\t", "COMM");
				break;
			case STT_TLS:
				(void) printf("%s\t", "TLS ");
				break;
			default:
				(void) printf("%d\t", type);
			}
			switch (bind) {
			case STB_LOCAL:
				(void) printf("LOCL");
				break;
			case STB_GLOBAL:
				(void) printf("GLOB");
				break;
			case STB_WEAK:
				(void) printf("WEAK");
				break;
			default:
				(void) printf("%d", bind);
			}
			(void) printf("\t  %d\t", EC_WORD(sym.st_other));

			if (specsec) {
				switch (shndx) {
				case SHN_UNDEF:
					(void) printf("UNDEF");
					break;
				case SHN_ABS:
					(void) printf("ABS");
					break;
				case SHN_COMMON:
					(void) printf("COMMON");
					break;
				case SHN_XINDEX:
					(void) printf("XINDEX");
					break;
				default:
					(void) printf("%d", EC_WORD(shndx));
				}
			} else
				(void) printf("%d", EC_WORD(shndx));
			(void) printf("\t");
		}

		/* support machines where NULL-deref causes core dump */
		if (sym.st_name == 0)
			sym_name = (char *)UNKNOWN;
		else
			if (C_flag)
				sym_name = demangled_name(
					(char *)elf_strptr(elf_file,
					p_symtab->p_shdr.sh_link,
					sym.st_name));
		else
			sym_name = (char *)elf_strptr(elf_file,
				p_symtab->p_shdr.sh_link,
				sym.st_name);
		if (sym_name == NULL)
			sym_name = (char *)UNKNOWN;
		(void) printf("%s\n", sym_name);

		range--;
	}	/* end while */
}

/*
 * Print the section header table.  Input is the SCNTAB structure,
 * the number of sections, an index which is the number of the
 * section in the file, and the filename.  The values of the SCNTAB
 * structure, the number of sections, and the index are set in
 * dump_shdr depending on whether the -n or -d modifiers were set.
 */
static void
print_shdr(Elf *elf_file, SCNTAB *s, int num_scns, int index)
{
	SCNTAB *p;
	int num;
	int field;

	if (gelf_getclass(elf_file) == ELFCLASS64)
		field = 15;
	else
		field = 13;

	p = s;

	for (num = 0; num < num_scns; num++, p++) {
		(void) printf("[%d]\t", index++);
		if (!v_flag) {
			(void) printf("%u\t%llu\t",
			EC_WORD(p->p_shdr.sh_type),
			EC_XWORD(p->p_shdr.sh_flags));
		} else {
			switch (p->p_shdr.sh_type) {
			case SHT_NULL:
				(void) printf("NULL");
				break;
			case SHT_PROGBITS:
				(void) printf("PBIT");
				break;
			case SHT_SYMTAB:
				(void) printf("SYMT");
				break;
			case SHT_STRTAB:
				(void) printf("STRT");
				break;
			case SHT_RELA:
				(void) printf("RELA");
				break;
			case SHT_HASH:
				(void) printf("HASH");
				break;
			case SHT_DYNAMIC:
				(void) printf("DYNM");
				break;
			case SHT_NOTE:
				(void) printf("NOTE");
				break;
			case SHT_NOBITS:
				(void) printf("NOBI");
				break;
			case SHT_REL:
				(void) printf("REL ");
				break;
			case SHT_DYNSYM:
				(void) printf("DYNS");
				break;
			case ((GElf_Word) SHT_LOUSER):
				(void) printf("LUSR");
				break;
			case ((GElf_Word) SHT_HIUSER):
				(void) printf("HUSR");
				break;
			case SHT_SHLIB:
				(void) printf("SHLB");
				break;
			case SHT_SUNW_SIGNATURE:
				(void) printf("SIGN");
				break;
			case SHT_SUNW_ANNOTATE:
				(void) printf("ANOT");
				break;
			case SHT_SUNW_DEBUGSTR:
				(void) printf("DBGS");
				break;
			case SHT_SUNW_DEBUG:
				(void) printf("DBG ");
				break;
			case SHT_SUNW_move:
				(void) printf("MOVE");
				break;
			case SHT_SUNW_verdef:
				(void) printf("VERD");
				break;
			case SHT_SUNW_verneed:
				(void) printf("VERN");
				break;
			case SHT_SUNW_versym:
				(void) printf("VERS");
				break;
			case SHT_SUNW_syminfo:
				(void) printf("SYMI");
				break;
			case SHT_SUNW_COMDAT:
				(void) printf("COMD");
				break;
			default:
				(void) printf("%u", EC_WORD(p->p_shdr.sh_type));
				break;
			}
			(void) printf("    ");

			if (p->p_shdr.sh_flags & SHF_WRITE)
				(void) printf("W");
			else
				(void) printf("-");
			if (p->p_shdr.sh_flags & SHF_ALLOC)
				(void) printf("A");
			else
				(void) printf("-");
			if (p->p_shdr.sh_flags & SHF_EXECINSTR)
				(void) printf("I");
			else
				(void) printf("-");

			if (p->p_shdr.sh_flags & SHF_ORDERED)
				(void) printf("O");
			if (p->p_shdr.sh_flags & SHF_EXCLUDE)
				(void) printf("E");

			(void) printf("\t");

		}
		(void) printf("%-#*llx%-#*llx%-#*llx%s%s\n",
			field, EC_ADDR(p->p_shdr.sh_addr),
			field, EC_OFF(p->p_shdr.sh_offset),
			field, EC_XWORD(p->p_shdr.sh_size),
			/* compatibility:  tab for elf32 */
			(field == 13) ? "\t" : " ", p->scn_name);

		(void) printf("\t%u\t%u\t%-#*llx%-#*llx\n\n",
			EC_WORD(p->p_shdr.sh_link),
			EC_WORD(p->p_shdr.sh_info),
			field, EC_XWORD(p->p_shdr.sh_addralign),
			field, EC_XWORD(p->p_shdr.sh_entsize));
	}
}

/*
 * Check that a range of numbers is valid.  Input is
 * a lower bound, an upper bound, a boundary condition,
 * and the filename.  Negative numbers and numbers greater
 * than the bound are invalid.  low must be smaller than hi.
 * The returned integer is the number of items in the
 * range if it is valid and -1 otherwise.
 */
static int
check_range(int low, int hi, size_t bound, char *filename)
{
	if (((size_t)low > bound) || (low <= 0)) {
		(void) fprintf(stderr,
			"%s: %s: number out of range, %d\n",
			prog_name, filename, low);
		return (-1);
	}
	if (((size_t)hi > bound) || (hi < 0)) {
		(void) fprintf(stderr,
			"%s: %s: number out of range, %d\n",
			prog_name, filename, hi);
			return (-1);
	}

	if (hi && (low > hi)) {
		(void) fprintf(stderr,
			"%s: %s: invalid range, %d,%d\n",
			prog_name, filename, low, hi);
		return (-1);
	}
	if (hi)
		return (hi - low + 1);
	else
		return (1);
}

/*
 * Print relocation information.  Since this information is
 * machine dependent, new sections must be added for each machine
 * that is supported.  Input is an ELF file descriptor, the ELF header,
 * the SCNTAB structure, the number of sections, and a filename.
 * Set up necessary information to print relocation information
 * and call the appropriate print function depending on the
 * type of relocation information.  If the symbol table is
 * absent, no relocation data is processed.  Input is an
 * ELF file descriptor, the ELF header, the SCNTAB structure,
 * and the filename.  Set range of d_flag and name if n_flag.
 */
static void
dump_reloc_table(Elf *elf_file, GElf_Ehdr *p_ehdr,
	SCNTAB *p_scns, int num_scns, char *filename)
{
	Elf_Data *rel_data;
	Elf_Data *sym_data;
	size_t    sym_size;
	size_t    reloc_size;
	SCNTAB *reloc_symtab;
	SCNTAB *head_scns;
	int r_title = 0;
	int adj = 0;
	size_t shnum;

	if (gelf_getclass(elf_file) == ELFCLASS64)
		adj = 4;

	if ((!p_flag) && (!r_title)) {
		(void) printf("\n    **** RELOCATION INFORMATION ****\n");
		r_title = 1;
	}

	while (num_scns-- > 0) {
		if ((p_scns->p_shdr.sh_type != SHT_RELA) &&
		    (p_scns->p_shdr.sh_type != SHT_REL)) {
			p_scns++;
			continue;
		}

	head_scns = p_head_scns;

	if (elf_getshnum(elf_file, &shnum) == 0) {
		(void) fprintf(stderr,
			"%s: %s: elf_getshnum failed: %s\n",
			prog_name, filename, elf_errmsg(-1));
		return;
	}

	if ((p_scns->p_shdr.sh_link == 0) ||
	    /* LINTED */
	    (p_scns->p_shdr.sh_link >= (GElf_Word)shnum)) {
		(void) fprintf(stderr, "%s: %s: invalid sh_link field: "
			"section #: %d sh_link: %d\n",
			/* LINTED */
			prog_name, filename, (int)elf_ndxscn(p_scns->p_sd),
			(int)p_scns->p_shdr.sh_link);
		return;
	}
	head_scns += (p_scns->p_shdr.sh_link -1);

	if (head_scns->p_shdr.sh_type == SHT_SYMTAB) {
		reloc_symtab = p_symtab;
	} else if (head_scns->p_shdr.sh_type  == SHT_DYNSYM) {
		reloc_symtab = p_dynsym;
	} else {
		(void) fprintf(stderr,
"%s: %s: could not get symbol table\n", prog_name, filename);
		return;
	}

	sym_data = NULL;
	sym_size = 0;
	reloc_size = 0;

	if ((sym_data = elf_getdata(reloc_symtab->p_sd, NULL)) == NULL) {
		(void) fprintf(stderr,
		"%s: %s: no symbol table data\n", prog_name, filename);
		return;
	}
	sym_size = sym_data->d_size;

	if (p_scns == NULL) {
		(void) fprintf(stderr,
		"%s: %s: no section table data\n", prog_name, filename);
		return;
	}

	if (p_scns->p_shdr.sh_type == SHT_RELA) {
		if (!n_flag && r_flag)
			(void) printf("\n%s:\n", p_scns->scn_name);
		if (!p_flag && (!n_flag && r_flag))
			(void) printf("%-*s%-*s%-*s%s\n\n",
			    12 + adj, "Offset", 22, "Symndx",
			    18, "Type", "Addend");
		if ((rel_data = elf_getdata(p_scns->p_sd, NULL)) == NULL) {
			(void) fprintf(stderr,
"%s: %s: no relocation information\n", prog_name, filename);
			return;
		}
		reloc_size = rel_data->d_size;

		if (n_flag) {
			rn_flag = 1;
			print_rela(elf_file, p_scns, rel_data, sym_data, p_ehdr,
				reloc_size, sym_size, filename, reloc_symtab);
		}
		if (d_flag) {
			rn_flag = 0;
			print_rela(elf_file, p_scns, rel_data, sym_data, p_ehdr,
				reloc_size, sym_size, filename, reloc_symtab);
		}
		if (!n_flag && !d_flag)
			print_rela(elf_file, p_scns, rel_data, sym_data, p_ehdr,
				reloc_size, sym_size, filename, reloc_symtab);
	} else {
		if (p_scns->p_shdr.sh_type == SHT_REL) {
			if (!n_flag && r_flag)
				(void) printf("\n%s:\n", p_scns->scn_name);
			if (!p_flag && (!n_flag && r_flag)) {
				(void) printf("%-*s%-*s%s\n\n",
				    12 + adj, "Offset", 20, "Symndx", "Type");
			}
			if ((rel_data = elf_getdata(p_scns->p_sd, NULL))
			    == NULL) {
				(void) fprintf(stderr,
"%s: %s: no relocation information\n", prog_name, filename);
				return;
			}
			reloc_size = rel_data->d_size;
			if (n_flag) {
				rn_flag = 1;
				print_rel(elf_file, p_scns, rel_data, sym_data,
					p_ehdr, reloc_size, sym_size,
					filename, reloc_symtab);
			}
			if (d_flag) {
				rn_flag = 0;
				print_rel(elf_file, p_scns, rel_data, sym_data,
					p_ehdr, reloc_size, sym_size,
					filename, reloc_symtab);
			}
			if (!n_flag && !d_flag)
				print_rel(elf_file, p_scns, rel_data, sym_data,
					p_ehdr, reloc_size, sym_size,
					filename, reloc_symtab);
		}
	}
	p_scns++;
	}
}

/*
 * Print out the string tables.  Input is an opened ELF file,
 * the SCNTAB structure, the number of sections, and the filename.
 * Since there can be more than one string table, all sections are
 * examined and any with the correct type are printed out.
 */
static void
dump_string_table(SCNTAB *s, int num_scns)
{
	size_t section_size;
	unsigned char *strtab;
	int beg_of_string;
	int counter = 0;
	int str_off;
	int i;

	if (!p_flag) {
		(void) printf("\n     **** STRING TABLE INFORMATION ****\n");
	}

	for (i = 0; i < num_scns; i++, s++) {
		if (s->p_shdr.sh_type != SHT_STRTAB)
			continue;

		str_off = 0;

		if (!p_flag) {
			(void) printf("\n%s:\n", s->scn_name);
			(void) printf("   <offset>  \tName\n");
		}
		section_size = 0;
		if ((strtab = (unsigned char *)
		    get_scndata(s->p_sd, &section_size)) == NULL) {
			continue;
		}

		if (section_size != 0) {
			(void) printf("   <%d>  \t", str_off);
			beg_of_string = 0;
			while (section_size--) {
				unsigned char c = *strtab++;

				if (beg_of_string) {
					(void) printf("   <%d>  \t", str_off);
					counter++;
					beg_of_string = 0;
				}
				str_off++;
				switch (c) {
				case '\0':
					(void) printf("\n");
					beg_of_string = 1;
					break;
				default:
					(void) putchar(c);
				}
			}
		}
	}
	(void) printf("\n");
}

/*
 * Print the symbol table.  This function does not print the contents
 * of the symbol table but sets up the parameters and then calls
 * print_symtab to print the symbols.  Calling another function to print
 * the symbols allows both -T and -n to work correctly
 * simultaneously.  Input is an opened ELF file, a pointer to the
 * symbol table SCNTAB structure, and the filename.
 * Set the range of symbols to print if T_flag, and set
 * name of symbol to print if n_flag.
 */
static void
dump_symbol_table(Elf *elf_file, SCNTAB *p_symtab, char *filename)
{
	Elf_Data  *sym_data;
	GElf_Sym  T_range, n_range;	/* for use with -T and -n */
	size_t count = 0;
	size_t sym_size;
	int index = 1;
	int found_it = 0;
	int i;
	int adj = 0;			/*  field adjustment for elf64 */

	if (gelf_getclass(elf_file) == ELFCLASS64)
		adj = 4;

	if (p_symtab == NULL) {
		(void) fprintf(stderr,
		"%s: %s: could not get symbol table\n", prog_name, filename);
		return;
	}

	/* get symbol table data */
	sym_data = NULL;
	sym_size = 0;
	if ((sym_data =
	    elf_getdata(p_symtab->p_sd, NULL)) == NULL) {
		(void) printf("\n%s:\n", p_symtab->scn_name);
		(void) printf("No symbol table data\n");
		return;
	}
	sym_size = sym_data->d_size;

	count = sym_size / p_symtab->p_shdr.sh_entsize;

	if (n_flag && t_flag && !T_flag) {
		/* LINTED */
		for (i = 1; i < count; i++) {
			(void) gelf_getsym(sym_data, i, &n_range);
			if (strcmp(name, (char *)
			    elf_strptr(elf_file,
			    p_symtab->p_shdr.sh_link,
			    n_range.st_name)) != 0) {
				continue;
			} else {
				found_it = 1;
				if (!p_flag) {
					(void) printf(
"\n              ***** SYMBOL TABLE INFORMATION *****\n");
					(void) printf(
"[Index]  %-*s%-*sType\tBind\tOther\tShndx\tName",
			    12 + adj, "Value", 9 + adj, "Size");
				}
				(void) printf("\n%s:\n", p_symtab->scn_name);
				print_symtab(elf_file, p_symtab, sym_data,
				    1, i);
			}
		}   /* end for */
		if (!found_it) {
			(void) fprintf(stderr, "%s: %s: %s not found\n",
			prog_name, filename, name);
		}
	} else if (T_flag) {
		T_num = check_range(T_low, T_hi, count, filename);
		if (T_num < 0)
			return;

		(void) gelf_getsym(sym_data, T_low-1, &T_range);
		index = T_low;

		if (!p_flag) {
			(void) printf(
"\n              ***** SYMBOL TABLE INFORMATION *****\n");
			(void) printf(
"[Index]  %-*s%-*sType\tBind\tOther\tShndx\tName",
			    12 + adj, "Value", 9 + adj, "Size");
		}
		(void) printf("\n%s:\n", p_symtab->scn_name);
		print_symtab(elf_file, p_symtab, sym_data, T_num, index);
	} else {
		if (!p_flag) {
			(void) printf(
"\n              ***** SYMBOL TABLE INFORMATION *****\n");
			(void) printf(
"[Index]  %-*s%-*sType\tBind\tOther\tShndx\tName",
			    12 + adj, "Value", 9 + adj, "Size");
		}
		(void) printf("\n%s:\n", p_symtab->scn_name);
		print_symtab(elf_file, p_symtab, sym_data, count-1, 1);
	}
}

/*
 * Print dynamic linking information.  Input is an ELF
 * file descriptor, the SCNTAB structure, the number of
 * sections, and the filename.
 */
static void
dump_dynamic(Elf *elf_file, SCNTAB *p_scns, int num_scns, char *filename)
{
	Elf_Data	*dyn_data;
	GElf_Dyn	p_dyn;
	GElf_Phdr	p_phdr;
	GElf_Ehdr	p_ehdr;
	char		*dt_name;
	int		index = 1;
	int		lib_scns = num_scns;
	SCNTAB		*l_scns = p_scns;
	int		header_num = 0;
#define	Fmttag		"%-15.15s "
#define	Fmtptr		"%#llx"

	if (!p_flag)
		(void) printf("\n  **** DYNAMIC SECTION INFORMATION ****\n");

	for (; num_scns > 0; num_scns--, p_scns++) {
		GElf_Word	link;
		int		ii;


		if (p_scns->p_shdr.sh_type != SHT_DYNAMIC)
			continue;

		if (!p_flag) {
			(void) printf("%s:\n", p_scns->scn_name);
			(void) printf("[INDEX]\tTag         Value\n");
		}

		if ((dyn_data = elf_getdata(p_scns->p_sd, NULL)) == 0) {
			(void) fprintf(stderr, "%s: %s: no data in "
			    "%s section\n", prog_name, filename,
			    p_scns->scn_name);
			return;
		}

		link = p_scns->p_shdr.sh_link;
		ii = 0;

		(void) gelf_getdyn(dyn_data, ii++, &p_dyn);
		while (p_dyn.d_tag != DT_NULL) {
			char	value[256];

			(void) printf("[%d]\t", index++);

			switch (p_dyn.d_tag) {
			/*
			 * Start of generic flags.
			 */
			case (DT_NEEDED):
				(void) printf(Fmttag, (const char *)"NEEDED");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
					    EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_PLTRELSZ):
				(void) printf(Fmttag, (const char *)"PLTSZ");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_PLTGOT):
				(void) printf(Fmttag, (const char *)"PLTGOT");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_HASH):
				(void) printf(Fmttag, (const char *)"HASH");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_STRTAB):
				(void) printf(Fmttag, (const char *)"STRTAB");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SYMTAB):
				(void) printf(Fmttag, (const char *)"SYMTAB");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_RELA):
				(void) printf(Fmttag, (const char *)"RELA");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_RELASZ):
				(void) printf(Fmttag, (const char *)"RELASZ");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_RELAENT):
				(void) printf(Fmttag, (const char *)"RELAENT");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_STRSZ):
				(void) printf(Fmttag, (const char *)"STRSZ");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_SYMENT):
				(void) printf(Fmttag, (const char *)"SYMENT");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_INIT):
				(void) printf(Fmttag, (const char *)"INIT");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_FINI):
				(void) printf(Fmttag, (const char *)"FINI");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SONAME):
				(void) printf(Fmttag, (const char *)"SONAME");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_RPATH):
				(void) printf(Fmttag, (const char *)"RPATH");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SYMBOLIC):
				(void) printf(Fmttag, (const char *)"SYMB");
				(void) printf("%s", (const char *)"(ignored)");
				break;
			case (DT_REL):
				(void) printf(Fmttag, (const char *)"REL");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_RELSZ):
				(void) printf(Fmttag, (const char *)"RELSZ");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_RELENT):
				(void) printf(Fmttag, (const char *)"RELENT");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_PLTREL):
				(void) printf(Fmttag, (const char *)"PLTREL");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_DEBUG):
				(void) printf(Fmttag, (const char *)"DEBUG");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_TEXTREL):
				(void) printf(Fmttag, (const char *)"TEXTREL");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_val));
				break;
			case (DT_JMPREL):
				(void) printf(Fmttag, (const char *)"JMPREL");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_BIND_NOW):
				(void) printf(Fmttag, (const char *)"BIND_NOW");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_val));
				break;
			case (DT_INIT_ARRAY):
				(void) printf(Fmttag,
					(const char *)"INIT_ARRAY");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_FINI_ARRAY):
				(void) printf(Fmttag,
					(const char *)"FINI_ARRAY");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_INIT_ARRAYSZ):
				(void) printf(Fmttag,
					(const char *)"INIT_ARRAYSZ");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_FINI_ARRAYSZ):
				(void) printf(Fmttag,
					(const char *)"FINI_ARRAYSZ");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_RUNPATH):
				(void) printf(Fmttag, (const char *)"RUNPATH");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_FLAGS):
				(void) printf(Fmttag,
				    (const char *)"FLAGS");
				value[0] = '\0';
				if (v_flag) {
					if (p_dyn.d_un.d_val & DF_ORIGIN)
					    (void) strcat(value,
						(const char *)"ORIGIN ");
					if (p_dyn.d_un.d_val & DF_SYMBOLIC)
					    (void) strcat(value,
						(const char *)"SYMBOLIC ");
					if (p_dyn.d_un.d_val & DF_TEXTREL)
					    (void) strcat(value,
						(const char *)"TEXTREL ");
					if (p_dyn.d_un.d_val & DF_BIND_NOW)
					    (void) strcat(value,
						(const char *)"BIND_NOW ");
					if (p_dyn.d_un.d_val & DF_STATIC_TLS)
					    (void) strcat(value,
						(const char *)"STATIC_TLS ");
				}
				if (v_flag && strlen(value))
					(void) printf("%s", value);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_PREINIT_ARRAY):
				(void) printf(Fmttag,
					(const char *)"PRINIT_ARRAY");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_PREINIT_ARRAYSZ):
				(void) printf(Fmttag,
					(const char *)"PRINIT_ARRAYSZ");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			/*
			 * DT_LOOS - DT_HIOS range.
			 */
			case (DT_SUNW_AUXILIARY):
				(void) printf(Fmttag,
					(const char *)"SUNW_AUXILIARY");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SUNW_RTLDINF):
				(void) printf(Fmttag,
					(const char *)"SUNW_RTLDINF");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SUNW_FILTER):
				(void) printf(Fmttag,
					(const char *)"SUNW_FILTER");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SUNW_CAP):
				(void) printf(Fmttag,
					(const char *)"SUNW_CAP");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;

			/*
			 * SUNW: DT_VALRNGLO - DT_VALRNGHI range.
			 */
			case (DT_CHECKSUM):
				(void) printf(Fmttag,
					(const char *)"CHECKSUM");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_PLTPADSZ):
				(void) printf(Fmttag,
					(const char *)"PLTPADSZ");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_MOVEENT):
				(void) printf(Fmttag,
					(const char *)"MOVEENT");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_MOVESZ):
				(void) printf(Fmttag,
					(const char *)"MOVESZ");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_FEATURE_1):
				(void) printf(Fmttag,
					(const char *)"FEATURE_1");
				value[0] = '\0';
				if (v_flag) {
					if (p_dyn.d_un.d_val & DTF_1_PARINIT)
					    (void) strcat(value,
						(const char *)"PARINIT ");
					if (p_dyn.d_un.d_val & DTF_1_CONFEXP)
					    (void) strcat(value,
						(const char *)"CONFEXP ");
				}
				if (v_flag && strlen(value))
					(void) printf("%s", value);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_POSFLAG_1):
				(void) printf(Fmttag,
					(const char *)"POSFLAG_1");
				value[0] = '\0';
				if (v_flag) {
					if (p_dyn.d_un.d_val & DF_P1_LAZYLOAD)
					    (void) strcat(value,
						(const char *)"LAZYLOAD ");
					if (p_dyn.d_un.d_val & DF_P1_GROUPPERM)
					    (void) strcat(value,
						(const char *)"GROUPPERM ");
				}
				if (v_flag && strlen(value))
					(void) printf("%s", value);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SYMINSZ):
				(void) printf(Fmttag,
					(const char *)"SYMINSZ");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_SYMINENT):
				(void) printf(Fmttag,
					(const char *)"SYMINENT");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;

			/*
			 * SUNW: DT_ADDRRNGLO - DT_ADDRRNGHI range.
			 */
			case (DT_CONFIG):
				(void) printf(Fmttag, (const char *)"CONFIG");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_DEPAUDIT):
				(void) printf(Fmttag,
					(const char *)"DEPAUDIT");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_AUDIT):
				(void) printf(Fmttag,
					(const char *)"AUDIT");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_PLTPAD):
				(void) printf(Fmttag,
					(const char *)"PLTPAD");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_MOVETAB):
				(void) printf(Fmttag,
					(const char *)"MOVETAB");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_SYMINFO):
				(void) printf(Fmttag,
					(const char *)"SYMINFO");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;

			/*
			 * SUNW: generic range.
			 */
			case (DT_RELACOUNT):
				(void) printf(Fmttag,
					(const char *)"RELACOUNT");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_RELCOUNT):
				(void) printf(Fmttag,
					(const char *)"RELCOUNT");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_FLAGS_1):
				(void) printf(Fmttag,
				    (const char *)"FLAGS_1");
				value[0] = '\0';
				if (v_flag) {
					if (p_dyn.d_un.d_val & DF_1_NOW)
					    (void) strcat(value,
						(const char *)"NOW ");
					if (p_dyn.d_un.d_val & DF_1_GLOBAL)
					    (void) strcat(value,
						(const char *)"GLOBAL ");
					if (p_dyn.d_un.d_val & DF_1_GROUP)
					    (void) strcat(value,
						(const char *)"GROUP ");
					if (p_dyn.d_un.d_val & DF_1_NODELETE)
					    (void) strcat(value,
						(const char *)"NODELETE ");
					if (p_dyn.d_un.d_val & DF_1_LOADFLTR)
					    (void) strcat(value,
						(const char *)"LOADFLTR ");
					if (p_dyn.d_un.d_val & DF_1_INITFIRST)
					    (void) strcat(value,
						(const char *)"INITFIRST ");
					if (p_dyn.d_un.d_val & DF_1_NOOPEN)
					    (void) strcat(value,
						(const char *)"NOOPEN ");
					if (p_dyn.d_un.d_val & DF_1_ORIGIN)
					    (void) strcat(value,
						(const char *)"ORIGIN ");
					if (p_dyn.d_un.d_val & DF_1_DIRECT)
					    (void) strcat(value,
						(const char *)"DIRECT ");
					if (p_dyn.d_un.d_val & DF_1_TRANS)
					    (void) strcat(value,
						(const char *)"TRANS ");
					if (p_dyn.d_un.d_val & DF_1_INTERPOSE)
					    (void) strcat(value,
						(const char *)"INTERPOSE ");
					if (p_dyn.d_un.d_val & DF_1_NODEFLIB)
					    (void) strcat(value,
						(const char *)"NODEFLIB ");
					if (p_dyn.d_un.d_val & DF_1_NODUMP)
					    (void) strcat(value,
						(const char *)"NODUMP ");
					if (p_dyn.d_un.d_val & DF_1_CONFALT)
					    (void) strcat(value,
						(const char *)"CONFALT ");
					if (p_dyn.d_un.d_val & DF_1_ENDFILTEE)
					    (void) strcat(value,
						(const char *)"ENDFILTEE ");
					if (p_dyn.d_un.d_val & DF_1_DISPRELDNE)
					    (void) strcat(value,
						(const char *)"DISPRELDONE ");
					if (p_dyn.d_un.d_val & DF_1_DISPRELPND)
					    (void) strcat(value,
						(const char *)"DISPRELPND ");
					if (p_dyn.d_un.d_val & DF_1_IGNMULDEF)
					    (void) strcat(value,
						(const char *)"IGNMULDEF ");
					if (p_dyn.d_un.d_val & DF_1_NOKSYMS)
					    (void) strcat(value,
						(const char *)"NOKSYMS ");
				}
				if (v_flag && strlen(value))
					(void) printf("%s", value);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_VERSYM):
				(void) printf(Fmttag, (const char *)"VERSYM");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_VERDEF):
				(void) printf(Fmttag, (const char *)"VERDEF");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_VERDEFNUM):
				(void) printf(Fmttag,
				    (const char *)"VERDEFNUM");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_VERNEED):
				(void) printf(Fmttag, (const char *)"VERNEED");
				(void) printf(Fmtptr,
					EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_VERNEEDNUM):
				(void) printf(Fmttag,
				    (const char *)"VERNEEDNUM");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_AUXILIARY):
				(void) printf(Fmttag,
					(const char *)"AUXILIARY");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_USED):
				(void) printf(Fmttag, (const char *)"USED");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;
			case (DT_FILTER):
				(void) printf(Fmttag, (const char *)"FILTER");
				if (v_flag)
					dt_name = (char *)elf_strptr(elf_file,
					    link, p_dyn.d_un.d_ptr);
				if (dt_name == NULL)
					dt_name = (char *)UNKNOWN;
				if (v_flag && strlen(dt_name))
					(void) printf("%s", dt_name);
				else
					(void) printf(Fmtptr,
						EC_ADDR(p_dyn.d_un.d_ptr));
				break;

			/*
			 * SUNW: machine specific range.
			 */
			case (DT_SPARC_REGISTER):
				(void) printf(Fmttag,
					(const char *)"REGISTER");
				(void) printf(Fmtptr,
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			case (DT_DEPRECATED_SPARC_REGISTER):
				(void) printf(Fmttag,
					(const char *)"REGISTER");
				(void) printf("%#llx  (deprecated value)",
					EC_XWORD(p_dyn.d_un.d_val));
				break;
			default:
				(void) printf("%lld", EC_XWORD(p_dyn.d_tag));
				break;
			}
			(void) printf("\n");
			(void) gelf_getdyn(dyn_data, ii++, &p_dyn);
		}
	}

	/*
	 * Check for existence of static shared library information.
	 */
	(void) gelf_getehdr(elf_file, &p_ehdr);
	while (header_num < p_ehdr.e_phnum) {
		(void) gelf_getphdr(elf_file, header_num, &p_phdr);
		if (p_phdr.p_type == PT_SHLIB) {
			while (--lib_scns > 0) {
				if (strcmp(l_scns->scn_name, ".lib") == 0) {
					print_static(l_scns, filename);
				}
				l_scns++;
			}
		}
		header_num++;
	}
}

/*
 * Print the ELF header.  Input is an ELF file descriptor
 * and the filename.  If f_flag is set, the ELF header is
 * printed to stdout, otherwise the function returns after
 * setting the pointer to the ELF header.  Any values which
 * are not known are printed in decimal.  Fields must be updated
 * as new values are added.
 */
static GElf_Ehdr *
dump_elf_header(Elf *elf_file, char *filename, GElf_Ehdr * elf_head_p)
{
	int class, data;
	int field;

	if (gelf_getehdr(elf_file, elf_head_p) == NULL) {
		(void) fprintf(stderr,
		"%s: %s: %s\n", prog_name, filename, elf_errmsg(-1));
		return (NULL);
	}

	class = (int)elf_head_p->e_ident[4];

	if (class == ELFCLASS64)
		field = 17;
	else
		field = 13;

	if (!f_flag)
		return (elf_head_p);

	if (!p_flag) {
	(void) printf(
		"\n                    **** ELF HEADER ****\n");
	(void) printf("%-*s%-11s%-*sMachine     Version\n",
	    field, "Class", "Data", field, "Type");
	(void) printf("%-*s%-11s%-*sFlags       Ehsize\n",
	    field, "Entry", "Phoff", field, "Shoff");
	(void) printf("%-*s%-11s%-*sShnum       Shstrndx\n\n",
	    field, "Phentsize", "Phnum", field, "Shentsz");
	}

	if (!v_flag) {
		(void) printf("%-*d%-11d%-*d%-12d%d\n",
			field, elf_head_p->e_ident[4],
			elf_head_p->e_ident[5],
			field, (int)elf_head_p->e_type,
			(int)elf_head_p->e_machine,
			elf_head_p->e_version);
	} else {
		data = elf_head_p->e_ident[5];

		switch (class) {
		case ELFCLASSNONE:
			(void) printf("%-*s", field, "None");
			break;
		case ELFCLASS32:
			(void) printf("%-*s", field, "32-bit");
			break;
		case ELFCLASS64:
			(void) printf("%-*s", field, "64-bit");
			break;
		default:
			(void) printf("%-*d", field, class);
			break;
		}
		switch (data) {
		case ELFDATANONE:
			(void) printf("%-11s", "None   ");
			break;
		case ELFDATA2LSB:
			(void) printf("%-11s", "2LSB   ");
			break;
		case ELFDATA2MSB:
			(void) printf("%-11s", "2MSB   ");
			break;
		default:
			(void) printf("%-11d", data);
			break;
		}

		switch (elf_head_p->e_type) {
		case ET_NONE:
			(void) printf("%-*s", field, "None");
			break;
		case ET_REL:
			(void) printf("%-*s", field, "Reloc");
			break;
		case ET_EXEC:
			(void) printf("%-*s", field, "Exec");
			break;
		case ET_DYN:
			(void) printf("%-*s", field, "Dyn");
			break;
		case ET_CORE:
			(void) printf("%-*s", field, "Core");
			break;
		default:
			(void) printf("%-*d", field,
				EC_WORD(elf_head_p->e_type));
			break;
		}
		switch (elf_head_p->e_machine) {
		case EM_NONE:
			(void) printf("%-12s", "No mach");
			break;
		case EM_M32:
			(void) printf("%-12s", "WE32100");
			break;
		case EM_SPARC:
			(void) printf("%-12s", "SPARC");
			break;
		case EM_SPARCV9:
			(void) printf("%-12s", "SPARCV9");
			break;
		case EM_386:
			(void) printf("%-12s", "80386");
			break;
		case EM_68K:
			(void) printf("%-12s", "68000");
			break;
		case EM_88K:
			(void) printf("%-12s", "88000");
			break;
		case EM_486:
			(void) printf("%-12s", "80486");
			break;
		case EM_860:
			(void) printf("%-12s", "i860");
			break;
		case EM_MIPS:
			(void) printf("%-12s", "RS3000_BE");
			break;
		case EM_MIPS_RS3_LE:
			(void) printf("%-12s", "RS3000_LE");
			break;
		case EM_RS6000:
			(void) printf("%-12s", "RS6000");
			break;
		case EM_PA_RISC:
			(void) printf("%-12s", "PA_RISC");
			break;
		case EM_nCUBE:
			(void) printf("%-12s", "nCUBE");
			break;
		case EM_VPP500:
			(void) printf("%-12s", "VPP500");
			break;
		case EM_SPARC32PLUS:
			(void) printf("%-12s", "SPARC32PLUS");
			break;
		case EM_PPC:
			(void) printf("%-12s", "PowerPC");
			break;
		case EM_IA_64:
			(void) printf("%-12s", "IA64");
			break;
		default:
			(void) printf("%-12d", EC_WORD(elf_head_p->e_machine));
		}
		switch (elf_head_p->e_version) {
		case EV_NONE:
			(void) printf("Invalid\n");
			break;
		case EV_CURRENT:
			(void) printf("Current\n");
			break;
		default:
			(void) printf("%d\n", elf_head_p->e_version);
		}
	}
	(void) printf("%-#*llx%-#11llx%-#*llx%-#12x%#x\n",
		field, EC_ADDR(elf_head_p->e_entry),
		EC_OFF(elf_head_p->e_phoff),
		field, EC_OFF(elf_head_p->e_shoff),
		EC_WORD(elf_head_p->e_flags),
		EC_WORD(elf_head_p->e_ehsize));
	if (!v_flag || (elf_head_p->e_shstrndx != SHN_XINDEX)) {
		(void) printf("%-#*x%-11u%-#*x%-12u%u\n",
			field, EC_WORD(elf_head_p->e_phentsize),
			EC_WORD(elf_head_p->e_phnum),
			field, EC_WORD(elf_head_p->e_shentsize),
			EC_WORD(elf_head_p->e_shnum),
			EC_WORD(elf_head_p->e_shstrndx));
	} else {
		(void) printf("%-#*x%-11u%-#*x%-12uXINDEX\n",
			field, EC_WORD(elf_head_p->e_phentsize),
			EC_WORD(elf_head_p->e_phnum),
			field, EC_WORD(elf_head_p->e_shentsize),
			EC_WORD(elf_head_p->e_shnum));
	}
	if ((elf_head_p->e_shnum == 0) && (elf_head_p->e_shoff > 0)) {
		Elf_Scn		*scn;
		GElf_Shdr	shdr0;
		int		field;

		if (gelf_getclass(elf_file) == ELFCLASS64)
			field = 14;
		else
			field = 12;
		if (!p_flag) {
			(void) printf("\n	   **** SECTION HEADER[0] "
			    "{Elf Extensions} ****\n");
			(void) printf(
			    "[No]\tType\tFlags\t%-*s %-*s%-*s%sName\n",
			    field, "Addr", field, "Offset", field,
			    "Size(shnum)",
			    /* compatibility:  tab for elf32 */
			    (field == 12) ? "\t" : "  ");
			(void) printf("\tLn(strndx) Info\t%-*s Entsize\n",
			    field, "Adralgn");
		}
		if ((scn = elf_getscn(elf_file, 0)) == NULL) {
			(void) fprintf(stderr,
				"%s: %s: elf_getscn failed: %s\n",
				prog_name, filename, elf_errmsg(-1));
			return (NULL);
		}
		if (gelf_getshdr(scn, &shdr0) == 0) {
			(void) fprintf(stderr,
				"%s: %s: gelf_getshdr: %s\n",
				prog_name, filename, elf_errmsg(-1));
			return (NULL);
		}
		(void) printf("[0]\t%u\t%llu\t", EC_WORD(shdr0.sh_type),
			EC_XWORD(shdr0.sh_flags));

		/*
		 * LINTED - field and EC_XWORD cause -#*llu complaints that
		 * even this comment can't shutup.
		 */
		(void) printf("%-#*llx %-#*llx%-#*llu%s%-#*u\n",
			field, EC_ADDR(shdr0.sh_addr),
			field, EC_OFF(shdr0.sh_offset),
			field, EC_XWORD(shdr0.sh_size),
			/* compatibility:  tab for elf32 */
			((field == 12) ? "\t" : "  "),
			field, EC_WORD(shdr0.sh_name));

		(void) printf("\t%u\t%u\t%-#*llx %-#*llx\n",
			EC_WORD(shdr0.sh_link),
			EC_WORD(shdr0.sh_info),
			field, EC_XWORD(shdr0.sh_addralign),
			field, EC_XWORD(shdr0.sh_entsize));
	}
	(void) printf("\n");

	return (elf_head_p);
}

/*
 * Print section contents.  Input is an ELF file descriptor,
 * the ELF header, the SCNTAB structure,
 * the number of symbols, and the filename.
 * The number of sections,
 * and the offset into the SCNTAB structure will be
 * set in dump_section if d_flag or n_flag are set.
 * If v_flag is set, sections which can be interpreted will
 * be interpreted, otherwise raw data will be output in hexidecimal.
 */
static void
print_section(Elf *elf_file,
	GElf_Ehdr *p_ehdr, SCNTAB *p, int num_scns, char *filename)
{
	unsigned char    *p_sec;
	int	i;
	size_t	size;

	for (i = 0; i < num_scns; i++, p++) {
		GElf_Shdr shdr;

		size = 0;
		if (s_flag && !v_flag)
			p_sec = (unsigned char *)get_rawscn(p->p_sd, &size);
		else
			p_sec = (unsigned char *)get_scndata(p->p_sd, &size);

		if ((gelf_getshdr(p->p_sd, &shdr) != NULL) &&
		    (shdr.sh_type == SHT_NOBITS)) {
			continue;
		}
		if (s_flag && !v_flag) {
			(void) printf("\n%s:\n", p->scn_name);
			print_rawdata(p_sec, size);
			continue;
		}
		if (shdr.sh_type == SHT_SYMTAB) {
			dump_symbol_table(elf_file, p, filename);
			continue;
		}
		if (shdr.sh_type == SHT_DYNSYM) {
			dump_symbol_table(elf_file, p, filename);
			continue;
		}
		if (shdr.sh_type == SHT_STRTAB) {
			dump_string_table(p, 1);
			continue;
		}
		if (shdr.sh_type == SHT_RELA) {
			dump_reloc_table(elf_file, p_ehdr, p, 1, filename);
			continue;
		}
		if (shdr.sh_type == SHT_REL) {
			dump_reloc_table(elf_file, p_ehdr, p, 1, filename);
			continue;
		}
		if (shdr.sh_type == SHT_DYNAMIC) {
			dump_dynamic(elf_file, p, 1, filename);
			continue;
		}

		(void) printf("\n%s:\n", p->scn_name);
		print_rawdata(p_sec, size);
	}
	(void) printf("\n");
}

/*
 * Print section contents. This function does not print the contents
 * of the sections but sets up the parameters and then calls
 * print_section to print the contents.  Calling another function to print
 * the contents allows both -d and -n to work correctly
 * simultaneously. Input is an ELF file descriptor, the ELF header,
 * the SCNTAB structure, the number of sections, and the filename.
 * Set the range of sections if d_flag, and set section name if
 * n_flag.
 */
static void
dump_section(Elf *elf_file,
	GElf_Ehdr *p_ehdr, SCNTAB *s, int num_scns, char *filename)
{
	SCNTAB *n_range, *d_range; /* for use with -n and -d modifiers */
	int i;
	int found_it = 0;  /* for use with -n section_name */

	if (n_flag) {
		n_range = s;

		for (i = 0; i < num_scns; i++, n_range++) {
			if ((strcmp(name, n_range->scn_name)) != 0)
				continue;
			else {
				found_it = 1;
				print_section(elf_file, p_ehdr,
					n_range, 1, filename);
			}
		}

		if (!found_it) {
			(void) fprintf(stderr, "%s: %s: %s not found\n",
				prog_name, filename, name);
		}
	} /* end n_flag */

	if (d_flag) {
		d_range = s;
		d_num = check_range(d_low, d_hi, num_scns, filename);
		if (d_num < 0)
			return;
		d_range += d_low - 1;

		print_section(elf_file, p_ehdr, d_range, d_num, filename);
	}	/* end d_flag */

	if (!n_flag && !d_flag)
		print_section(elf_file, p_ehdr, s, num_scns, filename);
}

/*
 * Print the section header table. This function does not print the contents
 * of the section headers but sets up the parameters and then calls
 * print_shdr to print the contents.  Calling another function to print
 * the contents allows both -d and -n to work correctly
 * simultaneously.  Input is the SCNTAB structure,
 * the number of sections from the ELF header, and the filename.
 * Set the range of section headers to print if d_flag, and set
 * name of section header to print if n_flag.
 */
static void
dump_shdr(Elf *elf_file, SCNTAB *s, int num_scns, char *filename)
{

	SCNTAB *n_range, *d_range;	/* for use with -n and -d modifiers */
	int field;
	int i;
	int found_it = 0;  /* for use with -n section_name */

	if (gelf_getclass(elf_file) == ELFCLASS64)
		field = 14;
	else
		field = 12;

	if (!p_flag) {
		(void) printf("\n	   **** SECTION HEADER TABLE ****\n");
		(void) printf("[No]\tType\tFlags\t%-*s %-*s %-*s%sName\n",
		    field, "Addr", field, "Offset", field, "Size",
		    /* compatibility:  tab for elf32 */
		    (field == 12) ? "\t" : "  ");
		(void) printf("\tLink\tInfo\t%-*s Entsize\n\n",
		    field, "Adralgn");
	}

	if (n_flag) {
		n_range = s;

		for (i = 1; i <= num_scns; i++, n_range++) {
			if ((strcmp(name, n_range->scn_name)) != 0)
				continue;
			else {
				found_it = 1;
				print_shdr(elf_file, n_range, 1, i);
			}
		}

		if (!found_it) {
			(void) fprintf(stderr, "%s: %s: %s not found\n",
				prog_name, filename, name);
		}
	} /* end n_flag */

	if (d_flag) {
		d_range = s;
		d_num = check_range(d_low, d_hi, num_scns, filename);
		if (d_num < 0)
			return;
		d_range += d_low - 1;

		print_shdr(elf_file, d_range, d_num, d_low);
	}	/* end d_flag */

	if (!n_flag && !d_flag)
		print_shdr(elf_file, s, num_scns, 1);
}

/*
 * Process all of the command line options (except
 * for -a, -g, -f, and -o).  All of the options processed
 * by this function require the presence of the section
 * header table and will not be processed if it is not present.
 * Set up a buffer containing section name, section header,
 * and section descriptor for each section in the file.  This
 * structure is used to avoid duplicate calls to libelf functions.
 * Structure members for the symbol table, the debugging information,
 * and the line number information are global.  All of the
 * rest are local.
 */
static void
dump_section_table(Elf *elf_file, GElf_Ehdr *elf_head_p, char *filename)
{

	static SCNTAB	*buffer, *p_scns;
	Elf_Scn		*scn = 0;
	char		*s_name = NULL;
	int		found = 0;
	unsigned int	num_scns;
	size_t		shstrndx;
	size_t		shnum;


	if (elf_getshnum(elf_file, &shnum) == 0) {
		(void) fprintf(stderr,
			"%s: %s: elf_getshnum failed: %s\n",
			prog_name, filename, elf_errmsg(-1));
		return;
	}
	if (elf_getshstrndx(elf_file, &shstrndx) == 0) {
		(void) fprintf(stderr,
			"%s: %s: elf_getshstrndx failed: %s\n",
			prog_name, filename, elf_errmsg(-1));
		return;
	}

	if ((buffer = calloc(shnum, sizeof (SCNTAB))) == NULL) {
		(void) fprintf(stderr, "%s: %s: cannot calloc space\n",
			prog_name, filename);
		return;
	}
	/* LINTED */
	num_scns = (int)shnum - 1;

	p_symtab = (SCNTAB *)0;
	p_dynsym = (SCNTAB *)0;
	p_scns = buffer;
	p_head_scns = buffer;

	while ((scn = elf_nextscn(elf_file, scn)) != 0) {
		if ((gelf_getshdr(scn, &buffer->p_shdr)) == 0) {
			(void) fprintf(stderr,
			"%s: %s: %s\n", prog_name, filename, elf_errmsg(-1));
			return;
		}
		s_name = (char *)elf_strptr(elf_file,
			shstrndx, buffer->p_shdr.sh_name);
		buffer->scn_name = s_name ? s_name : (char *)UNKNOWN;
		buffer->p_sd   =  scn;

		if (buffer->p_shdr.sh_type == SHT_SYMTAB) {
			found += 1;
			p_symtab = buffer;
		}
		if (buffer->p_shdr.sh_type == SHT_DYNSYM)
			p_dynsym = buffer;
		buffer++;
	}

	/*
	 * These functions depend upon the presence of the section header table
	 * and will not be invoked in its absence
	 */
	if (h_flag) {
		dump_shdr(elf_file, p_scns, num_scns, filename);
	}
	if (p_symtab && (t_flag || T_flag)) {
		dump_symbol_table(elf_file, p_symtab, filename);
	}
	if (c_flag) {
		dump_string_table(p_scns, num_scns);
	}
	if (r_flag) {
		dump_reloc_table(elf_file, elf_head_p,
			p_scns, num_scns, filename);
	}
	if (L_flag) {
		dump_dynamic(elf_file, p_scns, num_scns, filename);
	}
	if (s_flag) {
		dump_section(elf_file, elf_head_p, p_scns,
			num_scns, filename);
	}
}

/*
 * Load the archive string table(s) (for extended-length strings)
 * into an in-core table/list
 */
static struct stab_list_s *
load_arstring_table(struct stab_list_s *STabList,
	int fd, Elf *elf_file, Elf_Arhdr *p_ar, char *filename)
{
	off_t here;
	struct stab_list_s *STL_entry, *STL_next;

	if (p_ar) {
		STL_entry = malloc(sizeof (struct stab_list_s));
		STL_entry->next    = 0;
		STL_entry->strings = 0;
		STL_entry->size    = 0;

		if (!STabList)
			STabList = STL_entry;
		else {
			STL_next = STabList;
			while (STL_next->next != (void *)0)
				STL_next = STL_next->next;
			STL_next->next = STL_entry;
		}

		STL_entry->size    = p_ar->ar_size;
		STL_entry->strings = malloc(p_ar->ar_size);
		here = elf_getbase(elf_file);
		if ((lseek(fd, here, 0)) != here) {
			(void) fprintf(stderr,
			"%s: %s: could not lseek\n", prog_name, filename);
		}

		if ((read(fd, STL_entry->strings, p_ar->ar_size)) == -1) {
			(void) fprintf(stderr,
			"%s: %s: could not read\n", prog_name, filename);
		}
	}
	return (STabList);
}

/*
 * Print the archive header for each member of an archive.
 * Also call ar_sym_read to print the symbols in the
 * archive symbol table if g_flag.  Input is a file descriptor,
 * an ELF file descriptor, and the filename.  Putting the call
 * to dump the archive symbol table in this function is more
 * efficient since it is necessary to examine the archive member
 * name in the archive header to determine which member is the
 * symbol table.
 */
static void
dump_ar_hdr(int fd, Elf *elf_file, char *filename)
{
	extern int v_flag, g_flag, a_flag, p_flag;
	Elf_Arhdr  *p_ar;
	Elf *arf;
	Elf_Cmd cmd;
	int title = 0;
	int err = 0;

	char buf[DATESIZE];

	cmd = ELF_C_READ;
	while ((arf = elf_begin(fd, cmd, elf_file)) != 0) {
		p_ar = elf_getarhdr(arf);
		if (p_ar == NULL) {
			(void) fprintf(stderr,
			"%s: %s: %s\n", prog_name, filename, elf_errmsg(-1));
			continue;
		}
		if (strcmp(p_ar->ar_name, "/") == 0) {
			if (g_flag)
				ar_sym_read(elf_file, filename);
		} else if (strcmp(p_ar->ar_name, "//") == 0) {
			StringTableList = load_arstring_table(
				StringTableList, fd, arf, p_ar,
				filename);
			cmd = elf_next(arf);
			(void) elf_end(arf);
			continue;
		} else {
			if (a_flag) {
				(void) printf("%s[%s]:\n", filename,
					p_ar->ar_name);
				if (!p_flag && title == 0) {
					if (!v_flag)
						(void) printf(
"\n\n\t\t\t***ARCHIVE HEADER***"
"\n	Date          Uid     Gid    Mode      Size	 Member Name\n\n");
					else
						(void) printf(
"\n\n\t\t\t***ARCHIVE HEADER***"
"\n	Date                   Uid    Gid   Mode     Size     Member Name\n\n");
					title = 1;
				}
				if (!v_flag) {
					(void) printf(
"\t0x%.8lx  %6d  %6d  0%.6ho  0x%.8lx  %-s\n\n",
						p_ar->ar_date,
						(int)p_ar->ar_uid,
						(int)p_ar->ar_gid,
						(int)p_ar->ar_mode,
						p_ar->ar_size,
						p_ar->ar_name);
				} else {
					if ((strftime(buf, DATESIZE,
					    "%b %d %H:%M:%S %Y",
					    localtime(
					    &(p_ar->ar_date)))) == 0) {
						(void) fprintf(stderr,
"%s: %s: don't have enough space to store the date\n", prog_name, filename);
						exit(1);
					}
					(void) printf(
					"\t%s %6d %6d 0%.6ho 0x%.8lx %-s\n\n",
						buf,
						(int)p_ar->ar_uid,
						(int)p_ar->ar_gid,
						(int)p_ar->ar_mode,
						p_ar->ar_size,
						p_ar->ar_name);
				}
			}
		}
		cmd = elf_next(arf);
		(void) elf_end(arf);
	} /* end while */

	err = elf_errno();
	if (err != 0) {
		(void) fprintf(stderr,
		"%s: %s: %s\n", prog_name, filename, elf_errmsg(err));
	}
}

/*
 * Process member files of an archive.  This function provides
 * a loop through an archive equivalent the processing of
 * each_file for individual object files.
 */
static void
dump_ar_files(int fd, Elf *elf_file, char *filename)
{
	Elf_Arhdr  *p_ar;
	Elf *arf;
	Elf_Cmd cmd;
	Elf_Kind file_type;
	GElf_Ehdr elf_head;
	char *fullname;

	cmd = ELF_C_READ;
	while ((arf = elf_begin(fd, cmd, elf_file)) != 0) {
		p_ar = elf_getarhdr(arf);
		if (p_ar == NULL) {
			(void) fprintf(stderr,
				"%s: %s: %s\n",
				prog_name, filename, elf_errmsg(-1));
			return;
		}
		if ((strcmp(p_ar->ar_name, "/") == 0) ||
			(strcmp(p_ar->ar_name, "//") == 0)) {
			cmd = elf_next(arf);
			(void) elf_end(arf);
			continue;
		}

		fullname = malloc(strlen(filename) + strlen(p_ar->ar_name) + 3);
		(void) sprintf(fullname, "%s[%s]", filename, p_ar->ar_name);
		(void) printf("\n%s:\n", fullname);
		file_type = elf_kind(arf);
		if (file_type == ELF_K_ELF) {
			if (dump_elf_header(arf, fullname, &elf_head) == NULL)
				return;
			if (o_flag)
				dump_exec_header(arf,
					(unsigned)elf_head.e_phnum, fullname);
			if (x_flag)
				dump_section_table(arf, &elf_head, fullname);
		} else {
			(void) fprintf(stderr,
				"%s: %s: invalid file type\n",
				prog_name, fullname);
			cmd = elf_next(arf);
			(void) elf_end(arf);
			continue;
		}

		cmd = elf_next(arf);
		(void) elf_end(arf);
	} /* end while */
}

/*
 * Takes a filename as input.  Test first for a valid version
 * of libelf.a and exit on error.  Process each valid file
 * or archive given as input on the command line.  Check
 * for file type.  If it is an archive, process the archive-
 * specific options first, then files within the archive.
 * If it is an ELF object file, process it; otherwise
 * warn that it is an invalid file type.
 * All options except the archive-specific and program
 * execution header are processed in the function, dump_section_table.
 */
static void
each_file(char *filename)
{
	Elf *elf_file;
	GElf_Ehdr elf_head;
	int fd;
	Elf_Kind   file_type;

	struct stat buf;

	Elf_Cmd cmd;
	errno = 0;

	if (stat(filename, &buf) == -1) {
		(void) fprintf(stderr, "%s: ", prog_name);
		perror(filename);
		return;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr,
		"%s: Libelf is out of date\n", prog_name);
		exit(101);
	}

	if ((fd = open((filename), O_RDONLY)) == -1) {
		(void) fprintf(stderr, "%s: %s: cannot read\n",
			prog_name, filename);
		return;
	}
	cmd = ELF_C_READ;
	if ((elf_file = elf_begin(fd, cmd, (Elf *)0)) == NULL) {
		(void) fprintf(stderr,
		"%s: %s: %s\n", prog_name, filename, elf_errmsg(-1));
		return;
	}

	file_type = elf_kind(elf_file);
	if (file_type == ELF_K_AR) {
		if (a_flag || g_flag) {
			dump_ar_hdr(fd, elf_file, filename);
			elf_file = elf_begin(fd, cmd, (Elf *)0);
		}
		if (z_flag)
			dump_ar_files(fd, elf_file, filename);
	} else {
		if (file_type == ELF_K_ELF) {
			(void) printf("\n%s:\n", filename);
			if (dump_elf_header(elf_file, filename, &elf_head)
			    == (GElf_Ehdr *)0) {
					(void) elf_end(elf_file);
					(void) close(fd);
					return;
			}
			if (o_flag)
				dump_exec_header(elf_file,
					(unsigned)elf_head.e_phnum, filename);
			if (x_flag)
				dump_section_table(elf_file,
					&elf_head, filename);
		} else {
			(void) fprintf(stderr, "%s: %s: invalid file type\n",
				prog_name, filename);
			(void) elf_end(elf_file);
			(void) close(fd);
			return;
		}
	}
	(void) elf_end(elf_file);
	(void) close(fd);
}

/*
 * Sets up flags for command line options given and then
 * calls each_file() to process each file.
 */
int
main(int argc, char *argv[], char *envp[])
{
	char *optstr = OPTSTR; /* option string used by getopt() */
	int optchar;


	/*
	 * Check for a binary that better fits this architecture.
	 */
	conv_check_native(argv, envp);

	prog_name = argv[0];

	(void) setlocale(LC_ALL, "");
	while ((optchar = getopt(argc, argv, optstr)) != -1) {
		switch (optchar) {
		case 'a':
			a_flag = 1;
			x_flag = 1;
			break;
		case 'g':
			g_flag = 1;
			x_flag = 1;
			break;
		case 'v':
			v_flag = 1;
			break;
		case 'p':
			p_flag = 1;
			break;
		case 'f':
			f_flag = 1;
			z_flag = 1;
			break;
		case 'o':
			o_flag = 1;
			z_flag = 1;
			break;
		case 'h':
			h_flag = 1;
			x_flag = 1;
			z_flag = 1;
			break;
		case 's':
			s_flag = 1;
			x_flag = 1;
			z_flag = 1;
			break;
		case 'd':
			d_flag = 1;
			x_flag = 1;
			z_flag = 1;
			set_range(optarg, &d_low, &d_hi);
			break;
		case 'n':
			n_flag++;
			x_flag = 1;
			z_flag = 1;
			name = optarg;
			break;
		case 'r':
			r_flag = 1;
			x_flag = 1;
			z_flag = 1;
			break;
		case 't':
			t_flag = 1;
			x_flag = 1;
			z_flag = 1;
			break;
		case 'C':
			C_flag = 1;
			t_flag = 1;
			x_flag = 1;
			z_flag = 1;
			break;
		case 'T':
			T_flag = 1;
			x_flag = 1;
			z_flag = 1;
			set_range(optarg, &T_low, &T_hi);
			break;
		case 'c':
			c_flag = 1;
			x_flag = 1;
			z_flag = 1;
			break;
		case 'L':
			L_flag = 1;
			x_flag = 1;
			z_flag = 1;
			break;
		case 'V':
			V_flag = 1;
			(void) fprintf(stderr, "dump: %s %s\n",
			    (const char *)SGU_PKG,
			    (const char *)SGU_REL);
			break;
		case '?':
			errflag += 1;
			break;
		default:
			break;
		}
	}

	if (errflag || (optind >= argc) || (!z_flag && !x_flag)) {
		if (!(V_flag && (argc == 2))) {
			usage();
			exit(269);
		}
	}

	while (optind < argc) {
		each_file(argv[optind]);
		optind++;
	}
	return (0);
}
