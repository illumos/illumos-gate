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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gnu_msgfmt.h"

static char	*cmd;
int	fuzzy_flag = 0;
int	verbose_flag = 0;
int	strict_flag = 0;
int	po_error = 0;
char	*inputdir = NULL;
char	*outfile = NULL;
char	**po_names;

static void
usage(void)
{
	(void) fprintf(stderr,
		gettext(ERR_USAGE), cmd);
	exit(1);
}

int
main(int argc, char **argv)
{
	int	i, ret;
	static struct flags	flag;

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (cmd = strrchr(argv[0], '/'))
		++cmd;
	else
		cmd = argv[0];

	ret = parse_option(&argc, &argv, &flag);
	if (ret == -1) {
		usage();
		/* NOTREACHED */
	}
	if (flag.idir) {
		inputdir = flag.idir;
	}
	if (flag.ofile) {
		outfile = flag.ofile;
		catalog_init(outfile);
	}
	if (flag.fuzzy) {
		fuzzy_flag = 1;
	}
	if (flag.sun_p) {
		error(gettext(ERR_SUN_ON_GNU), cmd);
		/* NOTREACHED */
	}
	if (flag.verbose) {
		verbose_flag = 1;
	}
	if (flag.strict) {
		strict_flag = 1;
	}

	po_names = (char **)Xmalloc(argc * sizeof (char *));
	while (argc-- > 0) {
		if (verbose_flag) {
			diag(gettext(DIAG_START_PROC), *argv);
		}
		po_init(*argv);
		(void) yyparse();
		po_fini();
		argv++;
	}
	for (i = 0; i < cur_po_index; i++) {
		free(po_names[i]);
	}
	free(po_names);
	if (po_error) {
		/* error found */
		error(gettext(ERR_ERROR_FOUND), po_error);
		/* NOTREACHED */
	}
	output_all_gnu_mo_files();

	return (0);
}
