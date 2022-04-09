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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* UNIX HEADERS */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>

/* SIZE HEADER */
#include "defs.h"

/* RELEASE STRING */
#include "conv.h"
#include "sgs.h"


/* EXTERNAL VARIABLES DEFINED */
int		fflag = 0,	/* print full output if -f option is supplied */
		Fflag = 0,	/* print full output if -F option is supplied */
		nflag = 0;	/* include NOLOAD sections in size if -n */
				/* option  is supplied */
int		numbase = DECIMAL;
static int	errflag = 0;	/* Global error flag */
int		oneflag = 0;
int		exitcode = 0;   /* Global exit code */
char		*fname;
char		*archive;
int		is_archive = 0;

static char	*tool_name;

static void	usagerr();

#define	OPTSTR "VoxnfF"		/* option string for usage error message */
#define	GETOPTSTR "VoxnfF?"	/* option string for getopt */

static Elf	*elf;
static Elf_Arhdr	*arhdr;

/*
 *  main(argc, argv)
 *
 *  parses the command line
 *  opens, processes and closes each object file command line argument
 *
 *  defines:
 *      - int	numbase = HEX if the -x flag is in the command line
 *			= OCTAL if the -o flag is in the command line
 *			= DECIMAL if the -d flag is in the command line
 *
 *  calls:
 *      - process(filename) to print the size information in the object file
 *        filename
 *
 *  prints:
 *      - an error message if any unknown options appear on the command line
 *      - a usage message if no object file args appear on the command line
 *      - an error message if it can't open an object file
 *	      or if the object file has the wrong magic number
 *
 *  exits 1 - errors found, 0 - no errors
 */
int
main(int argc, char ** argv, char ** envp)
{
	/* UNIX FUNCTIONS CALLED */
	extern	void	error();

	/* SIZE FUNCTIONS CALLED */
	extern void process();

	/* EXTERNAL VARIABLES USED */
	extern int	numbase;
	extern int	errflag;
	extern int	oneflag;
	extern int	optind;
	extern char	*fname;

	int c;
	static int	fd;
	extern char	*archive;
	Elf_Cmd		cmd;
	Elf		*arf;
	unsigned	Vflag = 0;

	tool_name = argv[0];

	while ((c = getopt(argc, argv, GETOPTSTR)) != EOF) {
		switch (c) {
		case 'o':
			if (numbase != HEX)
				numbase = OCTAL;
			else
				(void) fprintf(stderr,
				"size: -x set, -o ignored\n");
			break;

		case 'd':
			numbase = DECIMAL;
			break;

		case 'x':
			if (numbase != OCTAL)
				numbase = HEX;
			else
				(void) fprintf(stderr,
				"size: -o set, -x ignored\n");
			break;

		case 'f':
			fflag++;
			break;

		case 'F':
			Fflag++;
			break;

		case 'n':
			nflag++;
			break;
		case 'V':
			(void) fprintf(stderr, "size: %s %s\n",
			    (const char *)SGU_PKG,
			    (const char *)SGU_REL);
			Vflag++;
			break;
		case '?':
			errflag++;
			break;
		default:
			break;
		}
	}
	if (errflag || (optind >= argc)) {
		if (!(Vflag && (argc == 2) && !errflag)) {
			usagerr();
		}
	}
	if ((argc - optind) == 1) {
		oneflag++;	/* only one file to process */
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, "size: Libelf is out of date");
		exit(FATAL);	/* library out of date */
	}

	for (; optind < argc; optind++) {
		fname = argv[optind];
		if ((fd = open(argv[optind], O_RDONLY)) == -1) {
			error(fname, "cannot open");
		} else {
			cmd = ELF_C_READ;
			arf = 0;

			if ((arf = elf_begin(fd, cmd, arf)) == 0) {
				/* error(fname, "cannot open"); */
				(void) fprintf(stderr,
				"size: %s: %s\n", fname, elf_errmsg(-1));
				return (FATAL);
			}

			if (elf_kind(arf) == ELF_K_AR) {
				archive = argv[optind];
			} else {
				archive = "";
			}

			while ((elf = elf_begin(fd, cmd, arf)) != 0) {
				if ((arhdr = elf_getarhdr(elf)) == 0) {
					if (elf_kind(arf) == ELF_K_NONE) {
						/* BEGIN CSTYLED */
						(void) fprintf(stderr,
						  "%s: %s: invalid file type\n",
						    tool_name, fname);
						/* END CSTYLED */
						exitcode++;
						break;
					} else {
						process(elf);
					}
				} else if (arhdr->ar_name[0] != '/') {
					fname = arhdr->ar_name;
					if (elf_kind(arf) == ELF_K_NONE) {
						/* BEGIN CSTYLED */
						(void) fprintf(stderr,
					    "%s: %s[%s]: invalid file type\n",
						    tool_name, archive, fname);
						/* END CSTYLED */
						exitcode++;
						break;
					} else {
						is_archive++;
						process(elf);
					}
				}
				cmd = elf_next(elf);
				(void) elf_end(elf);
			}
			(void) elf_end(arf);
			(void) close(fd);
		}
	}
	if (exitcode)
		exit(FATAL);
	else
		exit(0);
	return (0);
}

static void
usagerr()
{
	(void) fprintf(stderr,
	"usage: %s [-%s] file(s)...\n", tool_name, OPTSTR);
	exitcode++;
}
