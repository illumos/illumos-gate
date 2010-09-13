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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include "parser.h"
#include "errlog.h"

#define	SPEC_PARSER_VERSION "2.1"

char **filelist;

static char *prog;

static void usage(void);

int
main(int argc, char **argv)
{
	int c, retval, size = 0;
	int lflag = 0,
	    iflag = 0,
	    aflag = 0,
	    vflag = 0;
	char *tmpptr;

	Translator_info T_info;

	prog = basename(argv[0]);

	T_info.ti_verbosity = 0;
	T_info.ti_flags = 0;
	T_info.ti_dash_I = NULL;
	T_info.ti_output_file = NULL;
	T_info.ti_libtype = NORMALLIB;
	T_info.ti_versfile = "version";

	while ((c = getopt(argc, argv, "FVpd:v:l:o:I:a:")) != EOF) {
		switch (c) {
		case 'F':
			/* Library is a filter */
			T_info.ti_libtype = FILTERLIB;
			break;
		case 'a':
			/* set the target architecture */
			if ((T_info.ti_archtoken = arch_strtoi(optarg)) == 0) {
				errlog(ERROR,
				    "Error: architecture specified must "
				    "be one of: i386, sparc, sparcv9, "
				    "ia64 or amd64\n");
				usage();
			}
			T_info.ti_arch = optarg;
			++aflag;
			break;
		case 'V':
			/* print the version info */
			(void) fprintf(stderr,
			    "%s Version %s\n", prog, SPEC_PARSER_VERSION);
			return (0);
			break;
		case 'd':
			/* set debugging level */
			if (!isdigit(*optarg) ||
			    (T_info.ti_verbosity = atoi(optarg)) < 0) {
				errlog(ERROR,
				    "Error: -d option must be given a "
				    "positive integer argument\n");
				usage();
			}
			break;
		case 'l':
			/* set library name */
			++lflag;
			if (!isalnum(optarg[0])) {
				errlog(ERROR,
				    "Error: -l must be given the name of "
				    "a library as an argument\n");
				usage();
			}
			T_info.ti_liblist = optarg;
			break;
		case 'I':
			/* set path to spec files */
			++iflag;
			if (iflag == 1) {
				size = 1;
			} else {
				(void) strcat(T_info.ti_dash_I, ":");
				size = strlen(T_info.ti_dash_I);
			}
			tmpptr = realloc(T_info.ti_dash_I,
			    sizeof (char) * (size + strlen(optarg) + 3));
			if (tmpptr == NULL) {
				errlog(ERROR | FATAL,
				    "Error: Unable to allocate memory "
				    "for command line arguments\n");
			}
			T_info.ti_dash_I = tmpptr;
			if (iflag == 1) {
				(void) strcpy(T_info.ti_dash_I, optarg);
			} else {
				(void) strcat(T_info.ti_dash_I, optarg);
			}
			break;
		case 'v':
			/* set version filename */
			if (vflag != 0) {
				errlog(ERROR, "Error: Multiple -v options "
				    "in command line\n");
				usage();
			}
			T_info.ti_versfile = optarg;
			++vflag;
			break;
		case 'o':
			/* set name of output file */
			T_info.ti_output_file = optarg;
			break;
		case 'p':
			/* set picky flag */
			T_info.ti_flags = T_info.ti_flags | XLATOR_PICKY_FLAG;
			break;
		case '?':
		default:
			usage();
		}
	}

	if (lflag == 0) {
		errlog(ERROR,
		    "Error: -l library argument must be specified\n");
		usage();
	}
	if (aflag == 0) {
		errlog(ERROR, "Error: -a i386|sparc|sparcv9|ia64|amd64 "
			"argument must be specified\n");
		usage();
	}

	if (optind < argc) {
		filelist = &argv[optind];
	} else {
		filelist = NULL;
		errlog(ERROR, "Error: Must specify at least one spec "
			"file to process\n");
		usage();
	}

	T_info.ti_nfiles = argc-optind;
	seterrseverity(T_info.ti_verbosity);

	if (T_info.ti_dash_I == NULL) {
		T_info.ti_dash_I = ".";
	} else {
		(void) strcat(T_info.ti_dash_I, ":.");
	}

	errlog(STATUS, "using %s for spec path\n", T_info.ti_dash_I);

	if ((retval = frontend(&T_info)) != 0) {
		errlog(ERROR, "%d Error(s) occurred\n", retval);
		return (1);
	}
	return (0);
}

/*
 * usage()
 * prints the usage string and exits
 */
static void
usage(void)
{
	(void) fprintf(stderr, "Usage:\n\t%s [-d n] [-V] [ -v version_file] "
	    "-a i386|sparc|sparcv9|ia64|amd64 -l lib [-I path_to_spec ] "
	    "[-o outfile ] [-p] [-F] file.spec [ ... ]\n"
	    "Command line arguments:\n"
	    "  -d n             n is an integer specifying "
	    "the level of verbosity\n"
	    "  -V               Print the Version info\n"
	    "  -a arch          Target cpu architecture. "
	    "Must be one of\n"
	    "                   i386, sparc, sparcv9, ia64 or amd64\n"
	    "  -v version_file  Name of version file\n"
	    "  -o file          Name of output file\n"
	    "                   this option can only be used when "
	    "processing single\n                   spec files.  "
	    "Using this with multiple source .spec\n"
	    "                   filenames will cause "
	    "unpredictable results\n"
	    "  -l lib           library to process\n"
	    "  -I path_to_spec  path to spec files\n"
	    "  -p               be picky with interface versioning\n"
	    "  -F               library is a filter library\n", prog);
	exit(1);
}
