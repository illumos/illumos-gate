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
 * Copyright (c) 1988 AT&T
 * Copyright (c) 1989 AT&T
 * All Rights Reserved
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Jason King
 * Copyright 2019, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <locale.h>
#include <libelf.h>
#include <sys/elf_SPARC.h>


/* exit return codes */
#define	NOARGS	1
#define	BADELF	2
#define	NOALLOC 3

#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>

#include "sgs.h"
#include "conv.h"
#include "gelf.h"

typedef struct {		/* structure to translate symbol table data */
	int  indx;
	char *name;
	GElf_Addr value;
	GElf_Xword size;
	int type;
	int bind;
	unsigned char other;
	unsigned int shndx;
	unsigned int flags;	/* flags relevant to entry */
} SYM;

#define	FLG_SYM_SPECSEC	0x00000001	/* reserved scn index */
					/*	(SHN_ABS, SHN_COMMON, ...) */

#define	UNDEFINED "U"
#define	BSS_GLOB  "B"
#define	BSS_WEAK  "B*"
#define	BSS_LOCL  "b"
#define	BSS_SECN  ".bss"
#define	REG_GLOB  "R"
#define	REG_WEAK  "R*"
#define	REG_LOCL  "r"

#define	OPTSTR	":APDoxhvniursplLCVefgRTt:" /* option string for getopt() */

#define	DATESIZE 60

#define	TYPE 7
#define	BIND 3

#define	DEF_MAX_SYM_SIZE 256

static char *key[TYPE][BIND];

/*
 * Format type used for printing value and size items.
 * The non-negative values here are used as array indices into
 * several arrays found below. Renumbering, or adding items,
 * will require changes to those arrays as well.
 */
typedef enum {
	FMT_T_NONE = -1,	/* No format type yet assigned */

	/* The following are used as array indices */
	FMT_T_DEC = 0,
	FMT_T_HEX = 1,
	FMT_T_OCT = 2
} FMT_T;

/*
 * Determine whether a proposed format type is compatible with the current
 * setting. We allow setting the format as long as it hasn't already
 * been done, or if the new setting is the same as the current one.
 */
#define	COMPAT_FMT_FLAG(new_fmt_flag) \
	(fmt_flag == FMT_T_NONE) || (fmt_flag == new_fmt_flag)

static FMT_T fmt_flag = FMT_T_NONE;	/* format style to use for value/size */

static  int	/* flags: ?_flag corresponds to ? option */
	h_flag = 0,	/* suppress printing of headings */
	v_flag = 0,	/* sort external symbols by value */
	n_flag = 0,	/* sort external symbols by name */
	i_flag = 0,	/* don't sort symbols */
	u_flag = 0,	/* print only undefined symbols */
	r_flag = 0,	/* prepend object file or archive name */
			/* to each symbol name */
	R_flag = 0,	/* if "-R" issued then prepend archive name, */
			/* object file name to each symbol */
	s_flag = 0,	/* print section name instead of section index */
	p_flag = 0,	/* produce terse output */
	P_flag = 0,	/* Portable format output */
	l_flag = 0,	/* produce long listing of output */
	L_flag = 0,	/* print SUNW_LDYNSYM instead of SYMTAB */
	D_flag = 0,	/* print DYNSYM instead of SYMTAB */
	C_flag = 0,	/* print decoded C++ names */
	A_flag = 0,	/* File name */
	e_flag = 0,	/* -e flag */
	g_flag = 0,	/* -g flag */
	V_flag = 0;	/* print version information */
static char A_header[DEF_MAX_SYM_SIZE+1] = {0};

static char *prog_name;
static char *archive_name = (char *)0;
static int errflag = 0;
static void usage();
static void each_file(char *);
static void process(Elf *, char *);
static Elf_Scn * get_scnfd(Elf *, int, int);
static void get_symtab(Elf *, char *);
static SYM * readsyms(Elf_Data *, GElf_Sxword, Elf *, unsigned int,
			unsigned int);
static int compare(SYM *, SYM *);
static char *lookup(int, int);
static int  is_bss_section(unsigned int, Elf *, unsigned int);
static void print_ar_files(int, Elf *, char *);
static void print_symtab(Elf *, unsigned int, Elf_Scn *, GElf_Shdr *, char *);
static void parsename(char *);
static void parse_fn_and_print(const char *, char *);
static char d_buf[512];
static char p_buf[512];
static int exotic(const char *s);
static void set_A_header(char *);
static char *FormatName(char *, const char *);



/*
 * Parses the command line options and then
 * calls each_file() to process each file.
 */
int
main(int argc, char *argv[], char *envp[])
{
	char	*optstr = OPTSTR; /* option string used by getopt() */
	int	optchar;
	FMT_T	new_fmt_flag;

#ifndef	XPG4
	/*
	 * Check for a binary that better fits this architecture.
	 */
	(void) conv_check_native(argv, envp);
#endif

	/* table of keyletters for use with -p and -P options */
	key[STT_NOTYPE][STB_LOCAL] = "n";
	key[STT_NOTYPE][STB_GLOBAL] = "N";
	key[STT_NOTYPE][STB_WEAK] = "N*";
	key[STT_OBJECT][STB_LOCAL] = "d";
	key[STT_OBJECT][STB_GLOBAL] = "D";
	key[STT_OBJECT][STB_WEAK] = "D*";
	key[STT_FUNC][STB_LOCAL] = "t";
	key[STT_FUNC][STB_GLOBAL] = "T";
	key[STT_FUNC][STB_WEAK] = "T*";
	key[STT_SECTION][STB_LOCAL] = "s";
	key[STT_SECTION][STB_GLOBAL] = "S";
	key[STT_SECTION][STB_WEAK] = "S*";
	key[STT_FILE][STB_LOCAL] = "f";
	key[STT_FILE][STB_GLOBAL] = "F";
	key[STT_FILE][STB_WEAK] = "F*";
	key[STT_COMMON][STB_LOCAL] = "c";
	key[STT_COMMON][STB_GLOBAL] = "C";
	key[STT_COMMON][STB_WEAK] = "C*";
	key[STT_TLS][STB_LOCAL] = "l";
	key[STT_TLS][STB_GLOBAL] = "L";
	key[STT_TLS][STB_WEAK] = "L*";

	prog_name = argv[0];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((optchar = getopt(argc, argv, optstr)) != -1) {
		switch (optchar) {
		case 'o':
			if (COMPAT_FMT_FLAG(FMT_T_OCT)) {
				fmt_flag = FMT_T_OCT;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -x or -t set, -o ignored\n"),
				    prog_name);
			}
			break;
		case 'x':
			if (COMPAT_FMT_FLAG(FMT_T_HEX)) {
				fmt_flag = FMT_T_HEX;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -o or -t set, -x ignored\n"),
				    prog_name);
			}
			break;
		case 'h':
			h_flag = 1;
			break;
		case 'v':
			if (!n_flag && !i_flag) {
				v_flag = 1;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -n or -i set, -v ignored\n"),
				    prog_name);
			}
			break;
		case 'n':
			if (!v_flag && !i_flag) {
				n_flag = 1;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -v or -i set, -n ignored\n"),
				    prog_name);
			}
			break;
		case 'i':
			if (!n_flag && !v_flag) {
				i_flag = 1;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -n or -v set, -i ignored\n"),
				    prog_name);
			}
			break;
		case 'u':
			if (!e_flag && !g_flag) {
				u_flag = 1;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -e or -g set, -u ignored\n"),
				    prog_name);
			}
			break;
		case 'e':
			if (!u_flag && !g_flag) {
				e_flag = 1;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -u or -g set, -e ignored\n"),
				    prog_name);
			}
			break;
		case 'g':
			if (!u_flag && !e_flag) {
				g_flag = 1;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -u or -e set, -g ignored\n"),
				    prog_name);
			}
			break;
		case 'r':
			if (R_flag) {
				R_flag = 0;
				(void) fprintf(stderr, gettext(
				    "%s: -r set, -R ignored\n"),
				    prog_name);
			}
			r_flag = 1;
			break;
		case 's':
			s_flag = 1;
			break;
		case 'p':
			if (P_flag == 1) {
				(void) fprintf(stderr, gettext(
				    "nm: -P set. -p ignored\n"));
			} else {
				p_flag = 1;
			}
			break;
		case 'P':
			if (p_flag == 1) {
				(void) fprintf(stderr, gettext(
				    "nm: -p set. -P ignored\n"));
			} else {
				P_flag = 1;
			}
			break;
		case 'l':
			l_flag = 1;
			break;
		case 'L':
			if (D_flag == 1) {
				(void) fprintf(stderr, gettext(
				    "nm: -D set. -L ignored\n"));
			} else {
				L_flag = 1;
			}
			break;
		case 'D':
			if (L_flag == 1) {
				(void) fprintf(stderr, gettext(
				    "nm: -L set. -D ignored\n"));
			} else {
				D_flag = 1;
			}
			break;
		case 'C':
			C_flag = 1;
			break;
		case 'A':
			A_flag = 1;
			break;
		case 'V':
			V_flag = 1;
			(void) fprintf(stderr, "nm: %s %s\n",
			    (const char *)SGU_PKG,
			    (const char *)SGU_REL);
			break;
		case 'f':	/* -f is a noop, see man page */
			break;
		case 'R':
			if (!r_flag) {
				R_flag = 1;
			} else {
				(void) fprintf(stderr, gettext(
				    "%s: -r set, -R ignored\n"),
				    prog_name);
			}
			break;
		case 'T':
			break;
		case 't':
			if (strcmp(optarg, "o") == 0) {
				new_fmt_flag = FMT_T_OCT;
			} else if (strcmp(optarg, "d") == 0) {
				new_fmt_flag = FMT_T_DEC;
			} else if (strcmp(optarg, "x") == 0) {
				new_fmt_flag = FMT_T_HEX;
			} else {
				new_fmt_flag = FMT_T_NONE;
			}
			if (new_fmt_flag == FMT_T_NONE) {
				errflag += 1;
				(void) fprintf(stderr, gettext(
				    "nm: -t requires radix value (d, o, x): "
				    "%s\n"), optarg);
			} else if (COMPAT_FMT_FLAG(new_fmt_flag)) {
				fmt_flag = new_fmt_flag;
			} else {
				(void) fprintf(stderr, gettext(
				    "nm: -t or -o or -x set. -t ignored.\n"));
			}
			break;
		case ':':
			errflag += 1;
			(void) fprintf(stderr, gettext(
			    "nm: %c requires operand\n"), optopt);
			break;
		case '?':
			errflag += 1;
			break;
		default:
			break;
		}
	}

	if (errflag || (optind >= argc)) {
		if (!(V_flag && (argc == 2))) {
			usage();
			exit(NOARGS);
		}
	}

	/*
	 * If no explicit format style was specified, set the default
	 * here. In general, the default is for value and size items
	 * to be displayed in decimal format. The exception is that
	 * the default for -P is hexidecimal.
	 */
	if (fmt_flag == FMT_T_NONE)
		fmt_flag = P_flag ? FMT_T_HEX : FMT_T_DEC;


	while (optind < argc) {
		each_file(argv[optind]);
		optind++;
	}
	return (errflag);
}

/*
 * Print out a usage message in short form when program is invoked
 * with insufficient or no arguments, and in long form when given
 * either a ? or an invalid option.
 */
static void
usage()
{
	(void) fprintf(stderr, gettext(
"Usage: nm [-ACDhiLlnPpRrsTVv] [-efox] [-g | -u] [-t d|o|x] file ...\n"));
}

/*
 * Takes a filename as input.  Test first for a valid version
 * of libelf.a and exit on error.  Process each valid file
 * or archive given as input on the command line.  Check
 * for file type.  If it is an archive, call print_ar_files
 * to process each member of the archive in the same manner
 * as object files on the command line.  The same tests for
 * valid object file type apply to regular archive members.
 * If it is an ELF object file, process it; otherwise
 * warn that it is an invalid file type and return from
 * processing the file.
 */

static void
each_file(char *filename)
{
	Elf	*elf_file;
	int	fd;
	Elf_Kind   file_type;

	struct stat64 buf;

	Elf_Cmd cmd;
	errno = 0;
	if (stat64(filename, &buf) == -1)	{
		(void) fprintf(stderr, "%s: ", prog_name);
		perror(filename);
		errflag++;
		return;
	}
	if (elf_version(EV_CURRENT) == EV_NONE)	{
		(void) fprintf(stderr, gettext(
		    "%s: %s: libelf is out of date\n"),
		    prog_name, filename);
		exit(BADELF);
	}

	if ((fd = open((filename), O_RDONLY)) == -1) {
		(void) fprintf(stderr, gettext("%s: %s: cannot read file\n"),
		    prog_name, filename);
		errflag++;
		return;
	}
	cmd = ELF_C_READ;
	if ((elf_file = elf_begin(fd, cmd, (Elf *) 0)) == NULL)	{
		(void) fprintf(stderr,
		    "%s: %s: %s\n", prog_name, filename, elf_errmsg(-1));
		errflag++;
		(void) close(fd);
		return;
	}
	file_type = elf_kind(elf_file);
	if (file_type == ELF_K_AR) {
		print_ar_files(fd, elf_file, filename);
	} else {
		if (file_type == ELF_K_ELF) {
#ifndef XPG4
			if (u_flag && !h_flag) {
				/*
				 * u_flag is specified.
				 */
				if (p_flag)
					(void) printf("\n\n%s:\n\n", filename);
				else
					(void) printf(gettext(
				"\n\nUndefined symbols from %s:\n\n"),
					    filename);
			} else if ((h_flag == 0) && (P_flag == 0)) {
#else
			if ((h_flag == 0) && (P_flag == 0)) {
#endif
				if (p_flag) {
					(void) printf("\n\n%s:\n", filename);
				} else {
					if (A_flag != 0) {
						(void) printf("\n\n%s%s:\n",
						    A_header, filename);
					} else {
						(void) printf("\n\n%s:\n",
						    filename);
					}
				}
			}
			archive_name = (char *)0;
			process(elf_file, filename);
		} else {
			(void) fprintf(stderr, gettext(
			    "%s: %s: invalid file type\n"),
			    prog_name, filename);
			errflag++;
		}
	}
	(void) elf_end(elf_file);
	(void) close(fd);
}

/*
 * Get the ELF header and, if it exists, call get_symtab()
 * to begin processing of the file; otherwise, return from
 * processing the file with a warning.
 */
static void
process(Elf *elf_file, char *filename)
{
	GElf_Ehdr ehdr;

	if (gelf_getehdr(elf_file, &ehdr) == NULL) {
		(void) fprintf(stderr,
		    "%s: %s: %s\n", prog_name, filename, elf_errmsg(-1));
		return;
	}

	set_A_header(filename);
	get_symtab(elf_file, filename);
}

/*
 * Get section descriptor for the associated string table
 * and verify that the type of the section pointed to is
 * indeed of type STRTAB.  Returns a valid section descriptor
 * or NULL on error.
 */
static Elf_Scn *
get_scnfd(Elf * e_file, int shstrtab, int SCN_TYPE)
{
	Elf_Scn	*fd_scn;
	GElf_Shdr shdr;

	if ((fd_scn = elf_getscn(e_file, shstrtab)) == NULL) {
		return (NULL);
	}

	(void) gelf_getshdr(fd_scn, &shdr);
	if (shdr.sh_type != SCN_TYPE) {
		return (NULL);
	}
	return (fd_scn);
}


/*
 * Print the symbol table.  This function does not print the contents
 * of the symbol table but sets up the parameters and then calls
 * print_symtab to print the symbols.  This function does not assume
 * that there is only one section of type SYMTAB.  Input is an opened
 * ELF file, a pointer to the ELF header, and the filename.
 */
static void
get_symtab(Elf *elf_file, char *filename)
{
	Elf_Scn	*scn, *scnfd;
	Elf_Data *data;
	GElf_Word symtabtype;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf_file, &shstrndx) == -1) {
		(void) fprintf(stderr, gettext(
		    "%s: %s: cannot get e_shstrndx\n"),
		    prog_name, filename);
		return;
	}

	/* get section header string table */
	scnfd = get_scnfd(elf_file, shstrndx, SHT_STRTAB);
	if (scnfd == NULL) {
		(void) fprintf(stderr, gettext(
		    "%s: %s: cannot get string table\n"),
		    prog_name, filename);
		return;
	}

	data = elf_getdata(scnfd, NULL);
	if (data->d_size == 0) {
		(void) fprintf(stderr, gettext(
		    "%s: %s: no data in string table\n"),
		    prog_name, filename);
		return;
	}

	if (D_flag)
		symtabtype = SHT_DYNSYM;
	else if (L_flag)
		symtabtype = SHT_SUNW_LDYNSYM;
	else
		symtabtype = SHT_SYMTAB;

	scn = 0;
	while ((scn = elf_nextscn(elf_file, scn)) != 0)	{
		GElf_Shdr shdr;

		if (gelf_getshdr(scn, &shdr) == NULL) {
			(void) fprintf(stderr, "%s: %s: %s:\n",
			    prog_name, filename, elf_errmsg(-1));
			return;
		}

		if (shdr.sh_type == symtabtype)	{
			print_symtab(elf_file, shstrndx, scn,
			    &shdr, filename);
		}
	} /* end while */
}

/*
 * Process member files of an archive.  This function provides
 * a loop through an archive equivalent the processing of
 * each_file for individual object files.
 */
static void
print_ar_files(int fd, Elf * elf_file, char *filename)
{
	Elf_Arhdr  *p_ar;
	Elf	*arf;
	Elf_Cmd    cmd;
	Elf_Kind   file_type;


	cmd = ELF_C_READ;
	archive_name = filename;
	while ((arf = elf_begin(fd, cmd, elf_file)) != 0) {
		p_ar = elf_getarhdr(arf);
		if (p_ar == NULL) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    prog_name, filename, elf_errmsg(-1));
			return;
		}
		if (p_ar->ar_name[0] == '/') {
			cmd = elf_next(arf);
			(void) elf_end(arf);
			continue;
		}

		if ((h_flag == 0) && (P_flag == 0)) {
			if (p_flag) {
				(void) printf("\n\n%s[%s]:\n",
				    filename, p_ar->ar_name);
			} else {
				if (A_flag != 0)
					(void) printf("\n\n%s%s[%s]:\n",
					    A_header, filename, p_ar->ar_name);
				else
					(void) printf("\n\n%s[%s]:\n",
					    filename, p_ar->ar_name);
			}
		}
		file_type = elf_kind(arf);
		if (file_type == ELF_K_ELF) {
			process(arf, p_ar->ar_name);
		} else {
			(void) fprintf(stderr, gettext(
			    "%s: %s: invalid file type\n"),
			    prog_name, p_ar->ar_name);
			cmd = elf_next(arf);
			(void) elf_end(arf);
			errflag++;
			continue;
		}

		cmd = elf_next(arf);
		(void) elf_end(arf);
	} /* end while */
}

static void print_header(int);
#ifndef XPG4
static void print_with_uflag(SYM *, char *);
#endif
static void print_with_pflag(int, Elf *, unsigned int, SYM *, char *);
static void print_with_Pflag(int, Elf *, unsigned int, SYM *);
static void print_with_otherflags(int, Elf *, unsigned int,
		SYM *, char *);
/*
 * Print the symbol table according to the flags that were
 * set, if any.  Input is an opened ELF file, the section name,
 * the section header, the section descriptor, and the filename.
 * First get the symbol table with a call to elf_getdata.
 * Then translate the symbol table data in memory by calling
 * readsyms().  This avoids duplication of function calls
 * and improves sorting efficiency.  qsort is used when sorting
 * is requested.
 */
static void
print_symtab(Elf *elf_file, unsigned int shstrndx,
    Elf_Scn *p_sd, GElf_Shdr *shdr, char *filename)
{

	Elf_Data * sd;
	SYM	*sym_data;
	SYM	*s;
	GElf_Sxword	count = 0;
	const int ndigits_arr[] = {
		10,		/* FMT_T_DEC */
		8,		/* FMT_T_HEX */
		11,		/* FMT_T_OCT */
	};
	int ndigits;

	/*
	 * Determine # of digits to use for each numeric value.
	 */
	ndigits = ndigits_arr[fmt_flag];
	if (gelf_getclass(elf_file) == ELFCLASS64)
		ndigits *= 2;

	/*
	 * print header
	 */
	print_header(ndigits);

	/*
	 * get symbol table data
	 */
	if (((sd = elf_getdata(p_sd, NULL)) == NULL) || (sd->d_size == 0)) {
		(void) fprintf(stderr,
		    gettext("%s: %s: no symbol table data\n"),
		    prog_name, filename);
		return;
	}
	count = shdr->sh_size / shdr->sh_entsize;

	/*
	 * translate symbol table data
	 */
	sym_data = readsyms(sd, count, elf_file, shdr->sh_link,
	    (unsigned int)elf_ndxscn(p_sd));
	if (sym_data == NULL) {
		(void) fprintf(stderr, gettext(
		    "%s: %s: problem reading symbol data\n"),
		    prog_name, filename);
		return;
	}
	if (i_flag == 0) {
		qsort((char *)sym_data, count-1, sizeof (SYM),
		    (int (*)(const void *, const void *))compare);
	}
	s = sym_data;
	while (count > 1) {
#ifndef XPG4
		if (u_flag) {
			/*
			 * U_flag specified
			 */
			print_with_uflag(sym_data, filename);
		} else if (p_flag) {
#else
		if (p_flag) {
#endif
			print_with_pflag(ndigits, elf_file, shstrndx,
			    sym_data, filename);
		} else if (P_flag) {
			print_with_Pflag(ndigits, elf_file, shstrndx,
			    sym_data);
		} else {
			print_with_otherflags(ndigits, elf_file,
			    shstrndx, sym_data, filename);
		}
		sym_data++;
		count--;
	}

	free(s);		/* allocated in readsym() */
}

/*
 * Return appropriate keyletter(s) for -p option.
 * Returns an index into the key[][] table or NULL if
 * the value of the keyletter is unknown.
 */
static char *
lookup(int a, int b)
{
	return (((a < TYPE) && (b < BIND)) ? key[a][b] : NULL);
}

/*
 * Return TRUE(1) if the given section is ".bss" for "-p" option.
 * Return FALSE(0) if not ".bss" section.
 */
static int
is_bss_section(unsigned int shndx, Elf * elf_file, unsigned int shstrndx)
{
	Elf_Scn *scn		= elf_getscn(elf_file, shndx);
	char	*sym_name;

	if (scn != NULL) {
		GElf_Shdr shdr;
		(void) gelf_getshdr(scn, &shdr);
		sym_name = elf_strptr(elf_file, shstrndx, shdr.sh_name);
		if (strcmp(BSS_SECN, sym_name) == 0)
			return (1);
	}
	return (0);
}

/*
 * Translate symbol table data particularly for sorting.
 * Input is the symbol table data structure, number of symbols,
 * opened ELF file, and the string table link offset.
 */
static SYM *
readsyms(Elf_Data * data, GElf_Sxword num, Elf *elf,
    unsigned int link, unsigned int symscnndx)
{
	SYM		*s, *buf;
	GElf_Sym	sym;
	Elf32_Word	*symshndx = 0;
	unsigned int	nosymshndx = 0;
	int		i;

	if ((buf = calloc(num, sizeof (SYM))) == NULL) {
		(void) fprintf(stderr, gettext("%s: cannot allocate memory\n"),
		    prog_name);
		return (NULL);
	}

	s = buf;	/* save pointer to head of array */

	for (i = 1; i < num; i++, buf++) {
		(void) gelf_getsym(data, i, &sym);

		buf->indx = i;
		/* allow to work on machines where NULL-derefs dump core */
		if (sym.st_name == 0) {
			buf->name = "";
		} else if (C_flag) {
			const char *dn = NULL;
			char *name = (char *)elf_strptr(elf, link, sym.st_name);

			dn = conv_demangle_name(name);
			if (dn != name) {
				name = FormatName(name, dn);
				free((void *)dn);
			} else if (exotic(name)) {
				name = FormatName(name, d_buf);
			}
			buf->name = name;
		} else {
			buf->name = (char *)elf_strptr(elf, link, sym.st_name);
		}

		buf->value	= sym.st_value;
		buf->size	= sym.st_size;
		buf->type	= GELF_ST_TYPE(sym.st_info);
		buf->bind	= GELF_ST_BIND(sym.st_info);
		buf->other	= sym.st_other;
		if ((sym.st_shndx == SHN_XINDEX) &&
		    (symshndx == 0) && (nosymshndx == 0)) {
			Elf_Scn		*_scn;
			GElf_Shdr	_shdr;
			_scn = 0;
			while ((_scn = elf_nextscn(elf, _scn)) != 0) {
				if (gelf_getshdr(_scn, &_shdr) == 0)
					break;
				if ((_shdr.sh_type == SHT_SYMTAB_SHNDX) &&
				    (_shdr.sh_link == symscnndx)) {
					Elf_Data	*_data;
					if ((_data = elf_getdata(_scn,
					    0)) != 0) {
						symshndx =
						    (Elf32_Word *)_data->d_buf;
						break;
					}
				}
			}
			nosymshndx = 1;
		}
		if ((symshndx) && (sym.st_shndx == SHN_XINDEX)) {
			buf->shndx = symshndx[i];
		} else {
			buf->shndx	= sym.st_shndx;
			if (sym.st_shndx >= SHN_LORESERVE)
				buf->flags |= FLG_SYM_SPECSEC;
		}
	}	/* end for loop */
	return (s);
}

/*
 * compare either by name or by value for sorting.
 * This is the comparison function called by qsort to
 * sort the symbols either by name or value when requested.
 */
static int
compare(SYM *a, SYM *b)
{
	if (v_flag) {
		if (a->value > b->value)
			return (1);
		else
			return ((a->value == b->value) -1);
	} else
		return ((int)strcoll(a->name, b->name));
}

/*
 * Set up a header line for -A option.
 */
static void
set_A_header(char *fname)
{
	if (A_flag == 0)
		return;

	if (archive_name == (char *)0) {
		(void) snprintf(A_header, sizeof (A_header), "%s: ", fname);
	} else {
		(void) snprintf(A_header, sizeof (A_header), "%s[%s]: ",
		    archive_name, fname);
	}
}

/*
 * output functions
 *	The following functions are called from
 *	print_symtab().
 */

/*
 * Print header line if needed.
 *
 * entry:
 *	ndigits - # of digits to be used to format an integer
 *		value, not counting any '0x' (hex) or '0' (octal) prefix.
 */
static void
print_header(int ndigits)
{
	const char *fmt;
	const char *section_title;
	const int pad[] = {	/* Extra prefix characters for format */
		1,		/* FMT_T_DEC: '|' */
		3,		/* FMT_T_HEX: '|0x' */
		2,		/* FMT_T_OCT: '|0' */
	};
	if (
#ifndef XPG4
	    !u_flag &&
#endif
	    !h_flag && !p_flag && !P_flag) {
		(void) printf("\n");
		if (!s_flag) {
			fmt = "%-9s%-*s%-*s%-6s%-6s%-6s%-8s%s\n\n";
			section_title = "Shndx";
		} else {
			fmt = "%-9s%-*s%-*s%-6s%-6s%-6s%-15s%s\n\n";
			section_title = "Shname";
		}
		if (A_flag != 0)
			(void) printf("%s", A_header);
		ndigits += pad[fmt_flag];
		(void) printf(fmt, "[Index]", ndigits, " Value",
		    ndigits, " Size", "Type", "Bind",
		    "Other", section_title, "Name");
	}
}

/*
 * If the symbol can be printed, then return 1.
 * If the symbol can not be printed, then return 0.
 */
static int
is_sym_print(SYM *sym_data)
{
	/*
	 * If -u flag is specified,
	 *	the symbol has to be undefined.
	 */
	if (u_flag != 0) {
		if ((sym_data->shndx == SHN_UNDEF) &&
		    (strlen(sym_data->name) != 0))
			return (1);
		else
			return (0);
	}

	/*
	 * If -e flag is specified,
	 *	the symbol has to be global or static.
	 */
	if (e_flag != 0) {
		switch (sym_data->type) {
		case STT_NOTYPE:
		case STT_OBJECT:
		case STT_FUNC:
		case STT_COMMON:
		case STT_TLS:
			switch (sym_data->bind) {
			case STB_LOCAL:
			case STB_GLOBAL:
			case STB_WEAK:
				return (1);
			default:
				return (0);
			}
		default:
			return (0);
		}
	}

	/*
	 * If -g is specified,
	 *	the symbol has to be global.
	 */
	if (g_flag != 0) {
		switch (sym_data->type) {
		case STT_NOTYPE:
		case STT_OBJECT:
		case STT_FUNC:
		case STT_COMMON:
		case STT_TLS:
			switch (sym_data->bind) {
			case STB_GLOBAL:
			case STB_WEAK:
				return (1);
			default:
				return (0);
			}
		default:
			return (0);
		}
	}

	/*
	 * If it comes here, any symbol can be printed.
	 *	(So basically, -f is no-op.)
	 */
	return (1);
}

#ifndef XPG4
/*
 * -u flag specified
 */
static void
print_with_uflag(SYM *sym_data, char *filename)
{
	if ((sym_data->shndx == SHN_UNDEF) && (strlen(sym_data->name))) {
		if (!r_flag) {
			if (R_flag) {
				if (archive_name != (char *)0)
					(void) printf("   %s:%s:%s\n",
					    archive_name, filename,
					    sym_data->name);
				else
					(void) printf("    %s:%s\n",
					    filename, sym_data->name);
			}
			else
				(void) printf("    %s\n", sym_data->name);
		}
		else
			(void) printf("    %s:%s\n", filename, sym_data->name);
	}
}
#endif

/*
 * Print a symbol type representation suitable for the -p or -P formats.
 */
static void
print_brief_sym_type(Elf *elf_file, unsigned int shstrndx, SYM *sym_data)
{
	const char	*sym_key = NULL;

	if ((sym_data->shndx == SHN_UNDEF) && (strlen(sym_data->name)))
		sym_key = UNDEFINED;
	else if (sym_data->type == STT_SPARC_REGISTER) {
		switch (sym_data->bind) {
			case STB_LOCAL  : sym_key = REG_LOCL;
					break;
			case STB_GLOBAL : sym_key = REG_GLOB;
					break;
			case STB_WEAK   : sym_key = REG_WEAK;
					break;
			default	: sym_key = REG_GLOB;
					break;
		}
	} else if (((sym_data->flags & FLG_SYM_SPECSEC) == 0) &&
	    is_bss_section((int)sym_data->shndx, elf_file, shstrndx)) {
		switch (sym_data->bind) {
			case STB_LOCAL  : sym_key = BSS_LOCL;
					break;
			case STB_GLOBAL : sym_key = BSS_GLOB;
					break;
			case STB_WEAK   : sym_key = BSS_WEAK;
					break;
			default	: sym_key = BSS_GLOB;
					break;
		}

	} else {
		sym_key = lookup(sym_data->type, sym_data->bind);
	}

	if (sym_key != NULL) {
		if (!l_flag)
			(void) printf("%c ", sym_key[0]);
		else
			(void) printf("%-3s", sym_key);
	} else {
		if (!l_flag)
			(void) printf("%-2d", sym_data->type);
		else
			(void) printf("%-3d", sym_data->type);
	}
}

/*
 * -p flag specified
 */
static void
print_with_pflag(int ndigits, Elf *elf_file, unsigned int shstrndx,
    SYM *sym_data, char *filename)
{
	const char * const fmt[] = {
	    "%.*llu ",	/* FMT_T_DEC */
	    "0x%.*llx ",	/* FMT_T_HEX */
	    "0%.*llo "	/* FMT_T_OCT */
	};

	if (is_sym_print(sym_data) != 1)
		return;
	/*
	 * -A header
	 */
	if (A_flag != 0)
		(void) printf("%s", A_header);

	/*
	 * Symbol Value.
	 *	(hex/octal/decimal)
	 */
	(void) printf(fmt[fmt_flag], ndigits, EC_ADDR(sym_data->value));


	/*
	 * Symbol Type.
	 */
	print_brief_sym_type(elf_file, shstrndx, sym_data);

	if (!r_flag) {
		if (R_flag) {
			if (archive_name != (char *)0)
				(void) printf("%s:%s:%s\n", archive_name,
				    filename, sym_data->name);
			else
				(void) printf("%s:%s\n", filename,
				    sym_data->name);
		}
		else
			(void) printf("%s\n", sym_data->name);
	}
	else
		(void) printf("%s:%s\n", filename, sym_data->name);
}

/*
 * -P flag specified
 */
static void
print_with_Pflag(int ndigits, Elf *elf_file, unsigned int shstrndx,
    SYM *sym_data)
{
#define	SYM_LEN 10
	char sym_name[SYM_LEN+1];
	size_t len;
	const char * const fmt[] = {
		"%*llu %*llu \n",	/* FMT_T_DEC */
		"%*llx %*llx \n",	/* FMT_T_HEX */
		"%*llo %*llo \n"	/* FMT_T_OCT */
	};

	if (is_sym_print(sym_data) != 1)
		return;
	/*
	 * -A header
	 */
	if (A_flag != 0)
		(void) printf("%s", A_header);

	/*
	 * Symbol name
	 */
	len = strlen(sym_data->name);
	if (len >= SYM_LEN)
		(void) printf("%s ", sym_data->name);
	else {
		(void) sprintf(sym_name, "%-10s", sym_data->name);
		(void) printf("%s ", sym_name);
	}

	/*
	 * Symbol Type.
	 */
	print_brief_sym_type(elf_file, shstrndx, sym_data);

	/*
	 * Symbol Value & size
	 *	(hex/octal/decimal)
	 */
	(void) printf(fmt[fmt_flag], ndigits, EC_ADDR(sym_data->value),
	    ndigits, EC_XWORD(sym_data->size));
}

/*
 * other flags specified
 */
static void
print_with_otherflags(int ndigits, Elf *elf_file, unsigned int shstrndx,
    SYM *sym_data, char *filename)
{
	const char * const fmt_value_size[] = {
		"%*llu|%*lld|",		/* FMT_T_DEC */
		"0x%.*llx|0x%.*llx|",	/* FMT_T_HEX */
		"0%.*llo|0%.*llo|"	/* FMT_T_OCT */
	};
	const char * const fmt_int[] = {
		"%-5d",			/* FMT_T_DEC */
		"%#-5x",		/* FMT_T_HEX */
		"%#-5o"			/* FMT_T_OCT */
	};

	if (is_sym_print(sym_data) != 1)
		return;
	(void) printf("%s", A_header);
	(void) printf("[%d]\t|", sym_data->indx);
	(void) printf(fmt_value_size[fmt_flag], ndigits,
	    EC_ADDR(sym_data->value), ndigits, EC_XWORD(sym_data->size));

	switch (sym_data->type) {
	case STT_NOTYPE:(void) printf("%-5s", "NOTY"); break;
	case STT_OBJECT:(void) printf("%-5s", "OBJT"); break;
	case STT_FUNC:	(void) printf("%-5s", "FUNC"); break;
	case STT_SECTION:(void) printf("%-5s", "SECT"); break;
	case STT_FILE:	(void) printf("%-5s", "FILE"); break;
	case STT_COMMON: (void) printf("%-5s", "COMM"); break;
	case STT_TLS:	(void) printf("%-5s", "TLS "); break;
	case STT_SPARC_REGISTER: (void) printf("%-5s", "REGI"); break;
	default:
		(void) printf(fmt_int[fmt_flag], sym_data->type);
	}
	(void) printf("|");
	switch (sym_data->bind) {
	case STB_LOCAL:	(void) printf("%-5s", "LOCL"); break;
	case STB_GLOBAL:(void) printf("%-5s", "GLOB"); break;
	case STB_WEAK:	(void) printf("%-5s", "WEAK"); break;
	default:
		(void) printf("%-5d", sym_data->bind);
		(void) printf(fmt_int[fmt_flag], sym_data->bind);
	}
	(void) printf("|");
	(void) printf(fmt_int[fmt_flag], sym_data->other);
	(void)  printf("|");

	if (sym_data->shndx == SHN_UNDEF) {
		if (!s_flag)
			(void) printf("%-7s", "UNDEF");
		else
			(void) printf("%-14s", "UNDEF");
	} else if (sym_data->shndx == SHN_SUNW_IGNORE) {
		if (!s_flag)
			(void) printf("%-7s", "IGNORE");
		else
			(void) printf("%-14s", "IGNORE");
	} else if ((sym_data->flags & FLG_SYM_SPECSEC) &&
	    (sym_data->shndx == SHN_ABS)) {
		if (!s_flag)
			(void) printf("%-7s", "ABS");
		else
			(void) printf("%-14s", "ABS");
	} else if ((sym_data->flags & FLG_SYM_SPECSEC) &&
	    (sym_data->shndx == SHN_COMMON)) {
		if (!s_flag)
			(void) printf("%-7s", "COMMON");
		else
			(void) printf("%-14s", "COMMON");
	} else {
		if (s_flag) {
			Elf_Scn *scn = elf_getscn(elf_file, sym_data->shndx);
			GElf_Shdr shdr;

			if ((gelf_getshdr(scn, &shdr) != 0) &&
			    (shdr.sh_name != 0)) {
				(void) printf("%-14s",
				    (char *)elf_strptr(elf_file,
				    shstrndx, shdr.sh_name));
			} else {
				(void) printf("%-14d", sym_data->shndx);
			}
		} else {
			(void) printf("%-7d", sym_data->shndx);
		}
	}
	(void) printf("|");
	if (!r_flag) {
		if (R_flag) {
			if (archive_name != (char *)0)
				(void) printf("%s:%s:%s\n", archive_name,
				    filename, sym_data->name);
			else
				(void) printf("%s:%s\n", filename,
				    sym_data->name);
		}
		else
			(void) printf("%s\n", sym_data->name);
	}
	else
		(void) printf("%s:%s\n", filename, sym_data->name);
}

/*
 * C++ name demangling supporting routines
 */
static const char *ctor_str = "static constructor function for %s";
static const char *dtor_str = "static destructor function for %s";
static const char *ptbl_str = "pointer to the virtual table vector for %s";
static const char *vtbl_str = "virtual table for %s";

/*
 * alloc memory and create name in necessary format.
 * Return name string
 */
static char *
FormatName(char *OldName, const char *NewName)
{
	char *s = p_flag ?
	    "%s\n             [%s]" :
	    "%s\n\t\t\t\t\t\t       [%s]";
	size_t length = strlen(s)+strlen(NewName)+strlen(OldName)-3;
	char *hold = OldName;
	OldName = malloc(length);
	/*LINTED*/
	(void) snprintf(OldName, length, s, NewName, hold);
	return (OldName);
}


/*
 * Return 1 when s is an exotic name, 0 otherwise.  s remains unchanged,
 * the exotic name, if exists, is saved in d_buf.
 */
static int
exotic(const char *in_str)
{
	static char	*buff = 0;
	static size_t	buf_size;

	size_t		sym_len = strlen(in_str) + 1;
	int		tag = 0;
	char		*s;

	/*
	 * We will need to modify the symbol (in_str) as we are analyzing it,
	 * so copy it into a buffer so that we can play around with it.
	 */
	if (buff == NULL) {
		buff = malloc(DEF_MAX_SYM_SIZE);
		buf_size = DEF_MAX_SYM_SIZE;
	}

	if (sym_len > buf_size) {
		if (buff)
			free(buff);
		buff = malloc(sym_len);
		buf_size = sym_len;
	}

	if (buff == NULL) {
		(void) fprintf(stderr, gettext(
		    "%s: cannot allocate memory\n"), prog_name);
		exit(NOALLOC);
	}
	s = strcpy(buff, in_str);


	if (strncmp(s, "__sti__", 7) == 0) {
		s += 7; tag = 1;
		parse_fn_and_print(ctor_str, s);
	} else if (strncmp(s, "__std__", 7) == 0) {
		s += 7; tag = 1;
		parse_fn_and_print(dtor_str, s);
	} else if (strncmp(s, "__vtbl__", 8) == 0) {
		s += 8; tag = 1;
		parsename(s);
		(void) sprintf(d_buf, vtbl_str, p_buf);
	} else if (strncmp(s, "__ptbl_vec__", 12) == 0) {
		s += 12; tag = 1;
		parse_fn_and_print(ptbl_str, s);
	}
	return (tag);
}

void
parsename(char *s)
{
	register int len;
	char c, *orig = s;
	*p_buf = '\0';
	(void) strcat(p_buf, "class ");
	while (isdigit(*s)) s++;
	c = *s;
	*s = '\0';
	len = atoi(orig);
	*s = c;
	if (*(s+len) == '\0') { /* only one class name */
		(void) strcat(p_buf, s);
		return;
	} else
	{ /* two classname  %drootname__%dchildname */
		char *root, *child, *child_len_p;
		int child_len;
		root = s;
		child = s + len + 2;
		child_len_p = child;
		if (!isdigit(*child)) {
			/* ptbl file name */
			/*  %drootname__%filename */
			/* kludge for getting rid of '_' in file name */
			char *p;
			c = *(root + len);
			*(root + len) = '\0';
			(void) strcat(p_buf, root);
			*(root + len) = c;
			(void) strcat(p_buf, " in ");
			for (p = child; *p != '_'; ++p)
				;
			c = *p;
			*p = '.';
			(void) strcat(p_buf, child);
			*p = c;
			return;
		}

		while (isdigit(*child))
			child++;
		c = *child;
		*child = '\0';
		child_len = atoi(child_len_p);
		*child = c;
		if (*(child + child_len) == '\0') {
			(void) strcat(p_buf, child);
			(void) strcat(p_buf, " derived from ");
			c = *(root + len);
			*(root + len) = '\0';
			(void) strcat(p_buf, root);
			*(root + len) = c;
			return;
		} else {
			/* %drootname__%dchildname__filename */
			/* kludge for getting rid of '_' in file name */
			char *p;
			c = *(child + child_len);
			*(child + child_len) = '\0';
			(void) strcat(p_buf, child);
			*(child+child_len) = c;
			(void) strcat(p_buf, " derived from ");
			c = *(root + len);
			*(root + len) = '\0';
			(void) strcat(p_buf, root);
			*(root + len) = c;
			(void) strcat(p_buf, " in ");
			for (p = child + child_len + 2; *p != '_'; ++p)
				;
			c = *p;
			*p = '.';
			(void) strcat(p_buf, child + child_len + 2);
			*p = c;
			return;
		}
	}
}

void
parse_fn_and_print(const char *str, char *s)
{
	char		c = '\0', *p1, *p2;
	int		yes = 1;

	if ((p1 = p2 =  strstr(s, "_c_")) == NULL) {
		if ((p1 = p2 =  strstr(s, "_C_")) == NULL) {
			if ((p1 = p2 =  strstr(s, "_cc_")) == NULL) {
				if ((p1 = p2 =  strstr(s, "_cxx_")) == NULL) {
					if ((p1 = p2 = strstr(s, "_h_")) ==
					    NULL) {
						yes = 0;
					} else {
						p2 += 2;
					}
				} else {
					p2 += 4;
				}
			} else {
				p2 += 3;
			}
		} else {
			p2 += 2;
		}
	} else {
		p2 += 2;
	}

	if (yes) {
		*p1 = '.';
		c = *p2;
		*p2 = '\0';
	}

	for (s = p1;  *s != '_';  --s)
		;
	++s;

	(void) sprintf(d_buf, str, s);

	if (yes) {
		*p1 = '_';
		*p2 = c;
	}
}
