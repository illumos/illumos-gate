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
 *	Name:		getzonepath.c
 *
 *	Description:	Get the zone pathname associated with a label.
 *
 *	Usage:		getzonepath sensitivity_label
 */

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tsol/label.h>

static char	*prog;

static void
label_error(const char *label, const int err)
{
	if (errno == EINVAL) {
		switch (err) {
		case M_BAD_STRING:
			(void) fprintf(stderr,
			    gettext("%s: bad string %s\n"), prog, label);
		break;
		case M_BAD_LABEL:
			(void) fprintf(stderr,
			    gettext("%s: bad previous label\n"), prog);
		break;
		default:
			(void) fprintf(stderr,
			    gettext("%s: parsing error found in "
			    "\"%s\" at position %d\n"), prog, label, err);
		break;
		}
	} else {
		perror(prog);
	}
	exit(1);
}

int
main(int argc, char **argv)
{
	int		err = 0;
	m_label_t	*label = NULL;
	char		*zone_root;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it were'nt */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL)
		prog = argv[0];
	else
		prog++;

	if (argc != 2) {
		(void) fprintf(stderr, gettext(
		    "Usage: %s label\n"), prog);
		return (1);
	}

	if (str_to_label(argv[1], &label, MAC_LABEL, L_NO_CORRECTION,
	    &err) == -1) {
		label_error(argv[1], err);
	}

	if ((zone_root = getzonerootbylabel(label)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: cannot get path for label: %s.\n"), prog,
		    strerror(errno));
		return (3);
	}

	(void) printf("%s\n", zone_root);

	return (0);
} /* end main() */
