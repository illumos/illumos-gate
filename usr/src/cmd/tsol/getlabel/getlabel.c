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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	getlabel - gets file label.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <locale.h>
#include <tsol/label.h>

#define	s_flag	0x04
#define	S_flag	0x08


static int
get_label(char *filename, uint_t opt_flag)
{
	m_label_t *fl;
	char	*label;

	if ((fl = m_label_alloc(MAC_LABEL)) == NULL) {
		perror("m_label_alloc");
		return (1);
	} else if (getlabel(filename, fl) != 0) {
		perror(filename);
		m_label_free(fl);
		return (1);
	}

	(void) printf("%s:\t", filename);
	switch (opt_flag)  {
	case S_flag:
		if (label_to_str(fl, &label, M_LABEL, LONG_NAMES) != 0) {
			perror(gettext("%s:unable to translate "
			    "Sensitivity label"));
			m_label_free(fl);
			return (2);
		}
		break;
	case s_flag:
		if (label_to_str(fl, &label, M_LABEL, SHORT_NAMES) != 0) {
			perror(gettext("unable to translate "
			    "Sensitivity label"));
			m_label_free(fl);
			return (2);
		}
		break;
	default:
		if (label_to_str(fl, &label, M_LABEL, DEF_NAMES) != 0) {
			perror(gettext("unable to translate "
			    "Sensitivity label"));
			m_label_free(fl);
			return (2);
		}
		break;
	}
	(void) printf("%s\n", label);

	free(label);
	m_label_free(fl);
	return (0);
}

void
usage(char *prog)
{
	(void) fprintf(stderr, gettext("Usage: \n"));
	(void) fprintf(stderr, gettext("\t%s [-S | -s] filename ...\n"),
	    prog);
	exit(1);
}


int
main(int argc, char **argv)
{
	uint_t	opt_flag = 0;
	int	rc = 0;
	int	opt;
	char	*prog;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL)
		prog = argv[0];
	else
		prog++;

	if (argc < 2) {
		usage(prog);
	}

	while ((opt = getopt(argc, argv, ":sS")) != EOF) {
		switch (opt) {
		case 's':
			if (opt_flag != 0)
				usage(prog);
			opt_flag = s_flag;
			break;
		case 'S':
			if (opt_flag != 0)
				usage(prog);
			opt_flag = S_flag;
			break;
		default:
			usage(prog);
		}
	}
	if ((argc -= optind) < 1) {
		usage(prog);
	}
	argv += optind;
	while (argc-- > 0) {
		if (get_label(*argv++, opt_flag) != 0)
			rc = 2;
	}
	return (rc);
}
