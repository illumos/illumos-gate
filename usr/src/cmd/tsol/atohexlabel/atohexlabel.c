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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 *	atohexlabel - Convert a human readable label to its internal
 *			equivalent.
 */

#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>

#include <sys/param.h>

#include <tsol/label.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	 "SYS_TEST"
#endif	/* !defined(TEXT_DOMAIN) */

static void
label_error(const char *ascii, const int err)
{
	if (errno == EINVAL) {
		switch (err) {
		case M_BAD_STRING:
			(void) fprintf(stderr,
			    gettext("atohexlabel: bad string %s\n"), ascii);
		break;
		case M_BAD_LABEL:
			(void) fprintf(stderr,
			    gettext("atohexlabel: bad previous label\n"));
		break;
		default:
			(void) fprintf(stderr,
			    gettext("atohexlabel: parsing error found in "
			    "\"%s\" at position %d\n"), ascii, err);
		break;
		}
	} else {
		perror("atohexlabel");
	}
	exit(1);
	/*NOTREACHED*/
}

int
main(int argc, char **argv)
{
	int cflg = 0;			/* true if Clearance only */
	int errflg = 0;			/* true if arg error */
	m_label_t *label = NULL;	/* binary labels */
	char ascii[PIPE_BUF];		/* human readable label */
	char *hex = NULL;		/* internal label to print */
	int err = 0;			/* label error */
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;
	while ((c = getopt(argc, argv, "c")) != EOF) {

		switch (c) {
		case 'c':
			cflg++;
			break;

		default:
			errflg++;
			break;
		}
	}

	argc -= optind - 1;
	if (errflg || argc > 2) {

		(void) fprintf(stderr,
		    gettext("usage: %s [-c] [human readable label]\n"),
		    argv[0]);
		exit(1);
		/*NOTREACHED*/
	}

	if (argc == 2) {
		/* use label on command line */

		(void) strlcpy(ascii, argv[optind], sizeof (ascii));
	} else {
		/* read label from standard input */
		if ((c = read(STDIN_FILENO, ascii, sizeof (ascii))) <= 0) {
			perror(gettext("reading ASCII coded label"));
			exit(1);
			/*NOTREACHED*/
		}

		/*
		 * replace '\n' or (end of buffer) with end of string.
		 */
		ascii[c-1] = '\0';

		/*
		 * flush any remaining input past the size of the buffer.
		 */
		(void) ioctl(STDIN_FILENO, I_FLUSH, FLUSHR);
	}

	if (cflg) {
		if (str_to_label(ascii, &label, USER_CLEAR, L_NO_CORRECTION,
		    &err) == -1) {
			label_error(ascii, err);
		}
		if (label_to_str(label, &hex, M_INTERNAL, DEF_NAMES) != 0) {
			perror("label_to_str");
			exit(1);
		}
		(void) printf("%s\n", hex);
		m_label_free(label);
		free(hex);
	} else {
		if (str_to_label(ascii, &label, MAC_LABEL, L_NO_CORRECTION,
		    &err) == -1) {
			label_error(ascii, err);
		}
		if (label_to_str(label, &hex, M_INTERNAL, DEF_NAMES) != 0) {
			perror("label_to_str");
			exit(1);
		}
		(void) printf("%s\n", hex);
		m_label_free(label);
		free(hex);
	}

	return (0);		/* really exit(0); */
}
