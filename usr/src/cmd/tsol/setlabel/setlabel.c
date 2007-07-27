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
 *	setlabel - sets a file label.
 */

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <utmp.h>

#include <tsol/label.h>

static int	set_label(char *, char *);
static int	setlabel(char *, bslabel_t *);
static void	usage(void);
static void	m_label_err(const char *, const int);

static char *prog = NULL;

int
main(int argc, char **argv)
{
	int	rc = 0;
	char	*label;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL)
		prog = argv[0];
	else
		prog++;

	if (argc < 3) {
		usage();
		return (2);
	}

	argv++;
	argc--;

	label = *argv;
	argv++;
	argc--;
	while (argc-- > 0) {
		if (set_label(*argv++, label) != 0)
			rc = 1;
	}

	return (rc);
}

static int
set_label(char *filename, char *label)
{
	int rval = 0;
	int err;
	m_label_t *blabel;

	if ((blabel = m_label_alloc(MAC_LABEL)) == NULL) {
		(void) fprintf(stderr, "setlabel: ");
		perror(filename);
		return (2);
	}
	rval = getlabel(filename, blabel);
	if (rval) {
		(void) fprintf(stderr, "setlabel: ");
		perror(filename);
		return (rval);
	}
	if (!bslvalid(blabel)) {
		(void) fprintf(stderr,
		    gettext("%s: Current label is invalid\n"),
		    filename);
		blabel = NULL;
	}
	if (str_to_label(label, &blabel, MAC_LABEL, L_DEFAULT, &err) == -1) {
		m_label_err(label, err);
	}

	rval = setlabel(filename, blabel);
	if (rval == 0)
		m_label_free(blabel);
	return (rval);
}

static int
setlabel(char *filename, bslabel_t *label)
{
	int	rval;

	rval = setflabel(filename, label);

	if (rval) {
		(void) fprintf(stderr, "setlabel: ");
		perror(filename);
	}
	return (rval);
}

static void
m_label_err(const char *ascii, const int err)
{
	if (errno == EINVAL) {
		switch (err) {
		case M_BAD_STRING:
			(void) fprintf(stderr,
			    gettext("setlabel: bad string %s\n"), ascii);
		break;
		case M_BAD_LABEL:
			(void) fprintf(stderr,
			    gettext("setlabel: bad previous label\n"));
		break;
		default:
			(void) fprintf(stderr,
			    gettext("setlabel: parsing error found in "
			    "\"%s\" at position %d\n"), ascii, err);
		break;
		}
	} else {
		perror("setlabel");
	}
	exit(1);
}
/*
 * usage()
 *
 * This routine is called whenever there is a usage type of error has
 * occured.  For example, when a invalid option has has been specified.
 *
 */
static void
usage(void)
{

	(void) fprintf(stderr, gettext("Usage: \n"));
	(void) fprintf(stderr, gettext(
	    "	%s newlabel filename [...] \n"), prog);

}
