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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Create unique plain files or directories.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage: mktemp [-dqtu] [-p prefix_dir] [template]\n"));
	exit(1);
	/* NOTREACHED */
}

int
main(int argc, char **argv)
{
	int opt;
	char *prefix = NULL;
	boolean_t dounlink = B_FALSE;
	boolean_t domkdir = B_FALSE;
	boolean_t quiet = B_FALSE;
	boolean_t usetmpdir = B_FALSE;
	char template[] = "tmp.XXXXXX";
	char *tmpl;

	(void) setlocale(LC_ALL, "");

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;

	while ((opt = getopt(argc, argv, "dqtup:")) != EOF) {
		switch (opt) {
		case 'd':
			domkdir = B_TRUE;
			break;
		case 'q':
			quiet = B_TRUE;
			break;
		case 'p':
			prefix = optarg;
			/* FALLTHROUGH - -p implies -t */
		case 't':
			usetmpdir = B_TRUE;
			break;
		case 'u':
			dounlink = B_TRUE;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	switch (argc) {
	case 0:
		tmpl = template;
		usetmpdir = B_TRUE;
		break;
	case 1:
		tmpl = argv[0];
		break;
	default:
		usage();
	}

	if (usetmpdir) {
		char *tmp = getenv("TMPDIR");
		size_t len;

		if (strchr(tmpl, '/') != NULL) {
			(void) fprintf(stderr,
			    gettext("mktemp: template argument specified "
			    "with -t/-p option must not contain '/'"
			    "\n"));
			return (1);
		}
		/* TMPDIR overrides -p so that scripts will honor $TMPDIR */
		if (tmp != NULL)
			prefix = tmp;
		else if (prefix == NULL)
			prefix = "/tmp";

		len = snprintf(NULL, 0, "%s/%s", prefix, tmpl) + 1;
		tmp = malloc(len);
		if (tmp == NULL) {
			perror("malloc");
			return (1);
		}
		(void) snprintf(tmp, len, "%s/%s", prefix, tmpl);
		tmpl = tmp;
	}

	if (domkdir) {
		if (mkdtemp(tmpl) == NULL) {
			if (!quiet) {
				(void) fprintf(stderr,
				    gettext("mktemp: failed to create "
				    "directory: %s\n"), tmpl);
			}
			return (1);
		}
		if (dounlink)
			(void) rmdir(tmpl);
	} else {
		if (mkstemp(tmpl) < 0) {
			if (!quiet) {
				(void) fprintf(stderr,
				    gettext("mktemp: failed to create file: "
				    "%s\n"), tmpl);
			}
			return (1);
		}
		if (dounlink)
			(void) unlink(tmpl);
	}
	(void) puts(tmpl);
	return (0);
}
