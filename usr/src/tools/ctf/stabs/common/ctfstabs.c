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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program has two modes.
 *
 * In the first, or genassym, mode, it generates a header file containing
 * #define'd values for offsets and other information about requested
 * structures and arrays.  This header file can then be used by assembly
 * source files to access those structures without having to hard-code the
 * offsets.  The offsets and values in the header file are derived from the
 * CTF data in a provided object file.
 *
 * The second mode creates forthdebug macros for specified structures and
 * members from an object file.  The macros are created using the CTF data in
 * the object file.
 *
 * Forthdebug macros and offsets header files are generated using the same
 * tool for historical reasons.
 *
 * The input and output files, and their interaction with the tool are
 * shown below:
 *
 *  ---------------        -----------   cc -c -g    ------------------
 *  |#includes    | -----> |#includes| ------------> |object file with|
 *  |mode-specific|        -----------  ctfconvert   |    CTF data    |
 *  |   directives|				     ------------------
 *  ---------------					      |
 *	   |						      | obj_file
 *	   |						      V
 *	   |		   ------------			 ----------
 *	   \-------------> |directives| ---------------> |ctfstabs|
 *			   ------------  input_template  ----------
 *							      |
 *							      V
 *							---------------
 *	Mode-specific input and output formats are	|mode-specific|
 *	described in forth.c and genassym.c		|   output    |
 *							---------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ctf_headers.h"
#include "utils.h"
#include "memory.h"
#include "ctfstabs.h"

#define	WORD_LEN	256

static int lineno;

FILE *out;
ctf_file_t *ctf;

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: %s -t genassym [-m model] "
	    "[-i input_template] [-o output] obj_file\n", getpname());
	(void) fprintf(stderr, "       %s -t forth [-m model] "
	    "[-i input_template] [-o output] obj_file\n", getpname());
	exit(2);
}

/*PRINTFLIKE1*/
int
parse_warn(char *format, ...)
{
	va_list alist;

	(void) fprintf(stderr, "%s: Line %d: ", getpname(), lineno);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) fprintf(stderr, "\n");

	return (-1);
}

#define	READLINE_BUF_INCR	2

/*
 * Read a line of input into a statically-allocated buffer.  If the line
 * is larger than the buffer, the buffer will be dynamically resized.
 * Subsequent calls will overwrite the buffer.
 */
static char *
readline(FILE *fp)
{
	static char *buf, *bptr;
	static int buflen;

	if (buflen == 0) {
		buf = xmalloc(READLINE_BUF_INCR);
		buflen = READLINE_BUF_INCR;
	}

	bptr = buf;
	for (;;) {
		size_t len, off;

		if (fgets(bptr, buflen - (size_t)(bptr - buf), fp) == NULL)
			return (NULL);

		len = strlen(bptr);

		if (bptr[len - 1] == '\n')
			return (buf);

		off = (size_t)((bptr + len) - buf);
		buflen += READLINE_BUF_INCR;
		buf = xrealloc(buf, buflen);
		bptr = buf + off;
	}
}

/*
 * We're only given a type name.  Even if it's a struct or a union, we
 * still only get the struct or union name.  We therefore iterate through
 * the possible prefixes, trying to find the right type.
 */
ctf_id_t
find_type(char *name)
{
	char fullname[WORD_LEN];
	ctf_id_t id;

	if ((id = ctf_lookup_by_name(ctf, name)) != CTF_ERR)
		return (id);

	(void) snprintf(fullname, WORD_LEN, "struct %s", name);
	if ((id = ctf_lookup_by_name(ctf, fullname)) != CTF_ERR)
		return (id);

	(void) snprintf(fullname, WORD_LEN, "union %s", name);
	if ((id = ctf_lookup_by_name(ctf, fullname)) != CTF_ERR)
		return (id);

	(void) snprintf(fullname, WORD_LEN, "enum %s", name);
	if ((id = ctf_lookup_by_name(ctf, fullname)) != CTF_ERR)
		return (id);

	return (CTF_ERR);
}

static int
process_ifile(FILE *tmpl, proc_ops_t *ops)
{
	char *line;
	int skipping;
	size_t len;
	int err = 0;

	for (lineno = skipping = 0; (line = readline(tmpl)) != NULL; lineno++) {
		len = strlen(line) - 1;
		line[len] = '\0';

		if (len == 0)
			skipping = 0;

		if (skipping == 1)
			continue;

		if (ops->po_line(line) < 0) {
			(void) parse_warn("Error found: skipping to the next "
			    "blank line");
			err++;
			skipping = 1;
			continue;
		}
	}

	return (err > 0 ? -1 : 0);
}

static char *
get_model(ctf_file_t *ctf)
{
	ssize_t lsz;
	ctf_id_t lid;

	/* Neither of these should fail */
	if ((lid = ctf_lookup_by_name(ctf, "long")) == CTF_ERR ||
	    (lsz = ctf_type_size(ctf, lid)) == CTF_ERR)
		die("Couldn't get size of long in object file");

	if (lsz == 8)
		return ("lp64");
	else if (lsz == 4)
		return ("ilp32");
	else
		die("Unexpected size of long: %d bytes\n", lsz);

	return (NULL);
}

int
main(int argc, char **argv)
{
	char *model = NULL, *objfile = NULL, *outfile = NULL, *tmplfile = NULL;
	proc_ops_t *ops = &ga_ops;
	FILE *tmpl;
	int ctferr, c;

	while ((c = getopt(argc, argv, "i:m:o:t:")) != EOF) {
		switch (c) {
		case 'i':
			tmplfile = optarg;
			break;
		case 'm':
			model = optarg;
			break;
		case 't':
			if (strcmp(optarg, "genassym") == 0)
				ops = &ga_ops;
			else if (strcmp(optarg, "forth") == 0)
				ops = &fth_ops;
			else
				usage();
			break;

		case 'o':
			outfile = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc - optind != 1)
		usage();
	objfile = argv[optind];

	if (tmplfile == NULL || strcmp(tmplfile, "-") == 0)
		tmpl = stdin;
	else if ((tmpl = fopen(tmplfile, "r")) == NULL)
		die("Couldn't open template file %s", tmplfile);

	/*
	 * this can fail if ENOENT or if there's no CTF data in the file.
	 */
	if ((ctf = ctf_open(objfile, &ctferr)) == NULL) {
		die("Couldn't open object file %s: %s\n", objfile,
		    ctf_errmsg(ctferr));
	}

	if (model == NULL)
		model = get_model(ctf);
	else if (strcmp(model, get_model(ctf)) != 0)
		die("Model argument %s doesn't match the object file\n", model);

	if (outfile == NULL || strcmp(outfile, "-") == 0)
		out = stdout;
	else if ((out = fopen(outfile, "w")) == NULL)
		die("Couldn't open output file %s for writing", outfile);

	if ((ops->po_init != NULL && ops->po_init(model) < 0) ||
	    (process_ifile(tmpl, ops) < 0) ||
	    (ops->po_fini != NULL && ops->po_fini() < 0)) {
		(void) fclose(out);
		(void) unlink(outfile);
		return (1);
	}

	return (0);
}
