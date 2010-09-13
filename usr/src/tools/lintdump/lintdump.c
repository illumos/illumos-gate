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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)lintdump.c	1.6	06/06/04 SMI (from meem)"
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Tool for dumping lint libraries.
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "lnstuff.h"		/* silly header name from alint */

typedef struct lsu {
	const char	*name;
	ATYPE		atype;
	struct lsu	*next;
} lsu_t;

#define	LSU_HASHSIZE	512
static lsu_t		*lsu_table[LSU_HASHSIZE];

static boolean_t	showids = B_TRUE;
static boolean_t	justrelpaths = B_FALSE;
static int		justpass = -1;
static int		indentlevel = 9;
static const char	*progname;

static void info(const char *, ...);
static void infohdr(const char *, const char *, ...);
static void warn(const char *, ...);
static void die(const char *, ...);
static void usage(void);
static void indent(void);
static void unindent(void);
static void print_lintmod(const char *, FILE *, FLENS *);
static void print_pass(const char *, FILE *);
static void print_atype(ATYPE *, int, ATYPE *, const char *);
static void print_mods(const char *, ATYPE *, int, ATYPE *, uint_t);
static void getstr(FILE *, char *, size_t);
static void lsu_build(FILE *);
static void lsu_empty(void);
static int lsu_add(const char *, ATYPE *);
static lsu_t *lsu_lookup(unsigned long);

int
main(int argc, char **argv)
{
	int		i, c, mod;
	FILE		*fp;
	FLENS		hdr;
	const char	*lnname;

	progname = strrchr(argv[0], '/');
	if (progname == NULL)
		progname = argv[0];
	else
		progname++;

	while ((c = getopt(argc, argv, "ip:r")) != EOF) {
		switch (c) {
		case 'i':
			showids = B_FALSE;
			break;
		case 'p':
			justpass = strtoul(optarg, NULL, 0);
			if (justpass < 1 || justpass > 3)
				usage();
			break;
		case 'r':
			justrelpaths = B_TRUE;
			break;
		default:
			usage();
		}
	}

	if (optind == argc)
		usage();

	for (i = optind; i < argc; i++) {
		fp = fopen(argv[i], "r");
		if (fp == NULL) {
			warn("cannot open \"%s\"", argv[i]);
			continue;
		}

		lnname = argv[i];
		if (justrelpaths && lnname[0] == '/')
			lnname = strrchr(lnname, '/') + 1;

		/*
		 * Dump out all of the modules in the lint object.
		 */
		for (mod = 1; fread(&hdr, sizeof (hdr), 1, fp) == 1; mod++) {
			if (hdr.ver != LINTVER) {
				warn("%s: unsupported lint object version "
				    "%d\n", argv[i], hdr.ver);
				break;
			}

			if (mod == 1)
				infohdr("LINTOBJ", "%s\n", lnname);

			/*
			 * First build the table of structure/union names,
			 * then print the lint module.  Finally, empty the
			 * table out before dumping the next module.
			 */
			lsu_build(fp);
			print_lintmod(lnname, fp, &hdr);
			lsu_empty();
		}
		(void) fclose(fp);
	}

	return (EXIT_SUCCESS);
}

/*
 * Print a lint module and advance past it in the stream.
 */
static void
print_lintmod(const char *lnname, FILE *fp, FLENS *hp)
{
	ulong_t		psizes[5];
	uint_t		pass;

	psizes[0] = 0;
	psizes[1] = hp->f1;
	psizes[2] = hp->f2;
	psizes[3] = hp->f3;
	psizes[4] = hp->f4;

	infohdr("LINTMOD", "%hu: %lu+%lu+%lu+%lu = %lu bytes\n", hp->mno,
	    hp->f1, hp->f2, hp->f3, hp->f4, hp->f1 + hp->f2 + hp->f3 + hp->f4);

	for (pass = 1; pass <= 4; pass++) {
		if ((justpass < 0 || justpass == pass) && pass < 4) {
			infohdr("SECTION", "PASS%u: %lu bytes\n", pass,
			    psizes[pass]);
			print_pass(lnname, fp);
		} else {
			(void) fseek(fp, psizes[pass], SEEK_CUR);
		}
	}
}

/*
 * Print out a PASS section of a lint module.
 */
static void
print_pass(const char *lnname, FILE *fp)
{
	union rec	rec;
	int		nargs;
	char		name[1024];
	ATYPE		atype, *args;
	LINE		line;
	boolean_t	wasfile = B_FALSE;

	for (;;) {
		if (fread(&rec, sizeof (rec), 1, fp) != 1)
			die("%s: unexpected end of file\n", lnname);

		line = rec.l;
		if (line.decflag & LND)		/* end-of-pass marker */
			break;

		getstr(fp, name, sizeof (name));

		/*
		 * Check if this is a file record.
		 */
		if (line.decflag & LFN) {
			if (wasfile || !justrelpaths)
				infohdr("FILE", "%s\n", name);
			wasfile = B_TRUE;
			continue;
		}
		wasfile = B_FALSE;

		/*
		 * Check if this is a function or variable record.
		 */
		nargs = line.nargs;
		if (line.decflag & (LIB|LDS|LDI|LPR|LDX|LDC|LRV|LUE|LUV|LUM)) {
			if (nargs < 0)
				nargs = -nargs - 1;

			if (line.decflag & LDS)
				info("static ");
			else if (line.decflag & (LPR|LDX|LDC))
				info("extern ");

			args = calloc(sizeof (atype), nargs);
			if (args == NULL)
				die("cannot allocate argument information");

			if (fread(args, sizeof (atype), nargs, fp) != nargs)
				die("%s: unexpected end of file\n", lnname);

			print_atype(&line.type, line.nargs, args, name);
			free(args);

			if (line.decflag & LRV)
				info(" <returns value>");
			if (line.decflag & LUE)
				info(" <use: side-effects context>");
			if (line.decflag & LUV)
				info(" <use: return value context>");
			if (line.decflag & LUM)
				info(" <use: unspecified context>");

			if (line.decflag & LPF)
				info(" <PRINTFLIKE%d>", nargs);
			else if (line.decflag & LSF)
				info(" <SCANFLIKE%d>", nargs);

			if (line.decflag & LDI)
				info(" { <definition> }");
			else if (line.decflag & LDX)
				info(" = <definition>");

			info(";\n");
			continue;
		}

		/*
		 * Check if this is a structure or union record.
		 */
		if (line.decflag & LSU) {
			if (line.decflag & ~(LSU))
				info("??? ");

			info("struct ");
			if (name[0] != '.')
				info("%s ", name);
			if (showids)
				info("<tag %lu> ", line.type.extra.ty);
			info("{ \n");

			indent();
			for (; nargs > 0; nargs--) {
				if (fread(&atype, sizeof (atype), 1, fp) != 1) {
					die("%s: unexpected end of file\n",
					    lnname);
				}
				getstr(fp, name, sizeof (name));
				print_atype(&atype, 0, NULL, name);
				info(";\n");
			}
			unindent();
			info("};\n");
			continue;
		}

		warn("%s: unknown record type 0%o\n", lnname, line.decflag);
	}
}

/*
 * Print the C datatype or function `atp' named `name'.  If `name' is a
 * function, then `nargs' indicates the number of C datatypes pointed to
 * by `args'.
 */
static void
print_atype(ATYPE *atp, int nargs, ATYPE *args, const char *name)
{
	static const char *basetypes[] = {		"",
		"char",		"unsigned char",	"signed char",
		"short",	"unsigned short",	"signed short",
		"int",		"unsigned int",		"signed int",
		"long",		"unsigned long",	"signed long",
		"long long",	"unsigned long long",	"signed long long",
		"enum",		"float",		"double",
		"long double",	"void",			"struct",
		"union",	"_Bool",		"<genchar>",
		"<genshort>",	"<genint>",		"<genlong>",
		"<genlonglong>"
	};
	uint16_t basetype = atp->aty & LNQUAL;
	lsu_t *lsup;

	if (atp->aty & LCON)
		info("const ");
	if (atp->aty & LVOL)
		info("volatile ");
	if (atp->aty & LCONV)
		info("integer const ");

	if (basetype < 1 ||
	    basetype > (sizeof (basetypes) / sizeof (*basetypes)))
		info("<unknown type %x>", basetype);

	switch (basetype) {
	case LN_UNION:
	case LN_STRUCT:
		lsup = lsu_lookup(atp->extra.ty);
		if (lsup != NULL && lsup->name[0] != '.') {
			info("%s %s", basetypes[basetype], lsup->name);
		} else {
			info("%s", basetypes[basetype]);
			if (showids)
				info(" <tag %lu>", atp->extra.ty);
			else
				info(" <anon>");
		}
		break;
	default:
		info("%s", basetypes[basetype]);
	};

	print_mods(name, atp, nargs, args, 14);
}

/*
 * Recursively print type modifiers.
 */
static void
print_mods(const char *name, ATYPE *atp, int nargs, ATYPE *args, uint_t pos)
{
	int arg;
	int mods = atp->dcl_mod >> (pos * 2);
	int lastmods = atp->dcl_mod >> ((pos + 1) * 2);
	boolean_t isvarargs = B_FALSE;

	if (LN_ISPTR(mods)) {
		if (!LN_ISPTR(lastmods) && !LN_ISFTN(lastmods))
			info(" ");
		info("*");
	}

	if (atp->dcl_con & (1 << pos))
		info(" const ");
	if (atp->dcl_vol & (1 << pos))
		info(" volatile ");

	if (pos != 0) {
		if (LN_ISFTN(mods))
			info(" (");
		print_mods(name, atp, nargs, args, pos - 1);
		if (LN_ISFTN(mods))
			info(")()");
		return;
	}

	if (name[0] == '\0')
		return;

	if (!LN_ISPTR(lastmods) && !LN_ISPTR(mods))
		info(" ");
	info("%s", name);

	if (LN_ISARY(mods)) {
		info("[]");
	} else if (LN_ISFTN(mods)) {
		info("(");

		if (nargs < 0) {
			nargs = -nargs - 1;
			isvarargs = B_TRUE;
		}

		if (nargs == 0) {
			info("void");
		} else {
			for (arg = 0; arg < nargs; arg++) {
				print_atype(&args[arg], 0, NULL, "");
				if ((arg + 1) < nargs)
					info(", ");
				else if (isvarargs)
					info(", ...");
			}
		}
		info(")");
	}
}

/*
 * Add an LSU entry to the LSU table.
 */
static int
lsu_add(const char *name, ATYPE *atp)
{
	unsigned int	i = atp->extra.ty % LSU_HASHSIZE;
	lsu_t		*lsup;

	lsup = malloc(sizeof (lsu_t));
	if (lsup == NULL)
		return (ENOMEM);

	lsup->atype = *atp;
	lsup->next = lsu_table[i];
	lsup->name = strdup(name);
	if (lsup->name == NULL) {
		free(lsup);
		return (ENOMEM);
	}

	lsu_table[i] = lsup;
	return (0);
}

/*
 * Lookup an LSU entry by ID.
 */
static lsu_t *
lsu_lookup(T1WORD ty)
{
	unsigned int	i = ty % LSU_HASHSIZE;
	lsu_t		*lsup;

	for (lsup = lsu_table[i]; lsup != NULL; lsup = lsup->next) {
		if (lsup->atype.extra.ty == ty)
			return (lsup);
	}

	return (NULL);
}

/*
 * Read all LSU (structure and union definition) records in order to
 * build a structure and union name table, called the LSU table.
 * Although `fp' is read from, the original file offset is preserved.
 */
static void
lsu_build(FILE *fp)
{
	union rec	rec;
	char		name[1024];
	int		nargs;
	off_t		curoff = ftello(fp);

	for (;;) {
		if (fread(&rec, sizeof (rec), 1, fp) != 1)
			break;

		if (rec.l.decflag & LND)	/* end-of-pass marker */
			break;

		getstr(fp, name, sizeof (name));
		nargs = rec.l.nargs;

		if (rec.l.decflag & (LIB|LDS|LDI)) {
			if (nargs < 0)
				nargs = -nargs - 1;

			(void) fseek(fp, sizeof (ATYPE) * nargs, SEEK_CUR);
			continue;
		}

		if (rec.l.decflag & LSU) {
			if (lsu_add(name, &rec.l.type) != 0)
				warn("cannot allocate struct `%s' info", name);

			for (; nargs > 0; nargs--) {
				(void) fseek(fp, sizeof (ATYPE), SEEK_CUR);
				getstr(fp, name, sizeof (name));
			}
		}
	}

	(void) fseek(fp, curoff, SEEK_SET);
}

/*
 * Empty the LSU table.
 */
static void
lsu_empty(void)
{
	lsu_t		*lsup, *lsup_next;
	unsigned int	i;

	for (i = 0; i < LSU_HASHSIZE; i++) {
		for (lsup = lsu_table[i]; lsup != NULL; lsup = lsup_next) {
			lsup_next = lsup->next;
			free(lsup);
		}
		lsu_table[i] = NULL;
	}
}

/*
 * Read the NUL-terminated string at `fp' into `buf', which is at most
 * `bufsize' bytes.
 */
static void
getstr(FILE *fp, char *buf, size_t bufsize)
{
	int c;
	size_t i;

	for (i = 0; i < bufsize - 1; i++) {
		c = fgetc(fp);
		if (c == EOF || c == '\0' || !isascii(c))
			break;
		buf[i] = (char)c;
	}

	buf[i] = '\0';
}

static void
indent(void)
{
	indentlevel += 4;
}

static void
unindent(void)
{
	indentlevel -= 4;
}

static void
usage(void)
{
	(void) fprintf(stderr, "usage: %s [-i] [-p 1|2|3] [-r] lintobj"
	    " [ lintobj ... ]\n", progname);
	exit(EXIT_FAILURE);
}

/* PRINTFLIKE1 */
static void
info(const char *format, ...)
{
	va_list alist;
	static int complete = 1;

	if (complete)
		(void) printf("%*s", indentlevel, "");

	va_start(alist, format);
	(void) vprintf(format, alist);
	va_end(alist);

	complete = strrchr(format, '\n') != NULL;
}

/* PRINTFLIKE2 */
static void
infohdr(const char *hdr, const char *format, ...)
{
	va_list alist;
	static int complete = 1;

	if (complete)
		(void) printf("%7s: ", hdr);

	va_start(alist, format);
	(void) vprintf(format, alist);
	va_end(alist);

	complete = strrchr(format, '\n') != NULL;
}

/* PRINTFLIKE1 */
static void
warn(const char *format, ...)
{
	va_list alist;
	char *errstr = strerror(errno);

	(void) fprintf(stderr, "%s: warning: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", errstr);
}

/* PRINTFLIKE1 */
static void
die(const char *format, ...)
{
	va_list alist;
	char *errstr = strerror(errno);

	(void) fprintf(stderr, "%s: fatal: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", errstr);

	exit(EXIT_FAILURE);
}
