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
 *	lslabels - Display all labels dominating the specified label.
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
#include <sys/tsol/label_macro.h>
#include <iso/limits_iso.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	 "SYS_TEST"
#endif	/* !defined(TEXT_DOMAIN) */

int hflg = 0;			/* true if hex output */

/*
 * Compartment mask macros.
 */

typedef uint32_t comp_chunk_t;

#define	__NBWRD		(CHAR_BIT * sizeof (comp_chunk_t))
#define	COMP_BITS	(CHAR_BIT * sizeof (Compartments_t))
#define	compmask(n)	(1 << ((__NBWRD - 1) - ((n) % __NBWRD)))
#define	compword(n)	((n)/__NBWRD)

#define	COMP_ADDSET(a, p)	((comp_chunk_t *)(a))[compword(p)] |= \
				    compmask(p)
#define	COMP_DELSET(a, p)	((comp_chunk_t *)(a))[compword(p)] &= \
				    ~compmask(p)
#define	COMP_ISMEMBER(a, p)	((((comp_chunk_t *)(a))[compword(p)] & \
				    compmask(p)) != 0)

/* Need functions to test if bit is on */


void
bitfinder(m_label_t label, int next_bit) {
	char *labelstr = NULL;

	Compartments_t *comps = &label.compartments;

	while (next_bit < COMP_BITS) {
		if (COMP_ISMEMBER(comps, next_bit)) {
			bitfinder(label, next_bit + 1);
			COMP_DELSET(comps, next_bit);

			if (label_to_str(&label, &labelstr, M_LABEL,
			    LONG_NAMES) == 0) {
				m_label_t *label2 = NULL;
				int err;

				if (str_to_label(labelstr, &label2, MAC_LABEL,
				    L_NO_CORRECTION, &err) == 0) {
					if (!hflg) {
						(void) printf("%s\n", labelstr);
					} else {
						free(labelstr);
						(void) label_to_str(&label,
						    &labelstr, M_INTERNAL, 0);
						(void) printf("%s\n", labelstr);
					}
					m_label_free(label2);
				}
				free(labelstr);
			}
			bitfinder(label, next_bit + 1);
			break;
		}
		next_bit++;
		}
}

static void
label_error(const char *ascii, const int err)
{
	if (errno == EINVAL) {
		switch (err) {
		case M_BAD_STRING:
			(void) fprintf(stderr,
			    gettext("lslabels: bad string %s\n"), ascii);
		break;
		case M_BAD_LABEL:
			(void) fprintf(stderr,
			    gettext("lslabels: bad previous label\n"));
		break;
		default:
			(void) fprintf(stderr,
			    gettext("lslabels: parsing error found in "
			    "\"%s\" at position %d\n"), ascii, err);
		break;
		}
	} else {
		perror("lslabels");
	}
	exit(1);
	/*NOTREACHED*/
}

int
main(int argc, char **argv)
{
	int errflg = 0;			/* true if arg error */
	m_label_t *label = NULL;	/* binary labels */
	char ascii[PIPE_BUF];		/* human readable label */
	char *labelstr = NULL;		/* external label to start from */
	int err = 0;			/* label error */
	int c;
	int mode = M_LABEL;
	_Classification *level;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;
	while ((c = getopt(argc, argv, "h")) != EOF) {

		switch (c) {
		case 'h':
			hflg++;
			mode = M_INTERNAL;
			break;

		default:
			errflg++;
			break;
		}
	}

	argc -= optind - 1;
	if (errflg || argc > 2) {

		(void) fprintf(stderr,
		    gettext("usage: %s [-h] [label]\n"),
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

	if (str_to_label(ascii, &label, MAC_LABEL, L_NO_CORRECTION,
	    &err) == -1) {
		label_error(ascii, err);
	}
	if (label_to_str(label, &labelstr, mode,
	    DEF_NAMES) == 0) {
		(void) printf("%s\n", labelstr);
	}

	level =  &label->classification.class_u.class_chunk;
	while (*level > 0) {
		bitfinder(*label, 0);
		*level -= 1;
	}
	m_label_free(label);

	return (0);		/* really exit(0); */
}
