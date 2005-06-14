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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"
#include "sys/stat.h"
#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"
#include "form.h"

extern struct {
	char			*v;
	short			len;
	short			infile;
}			formheadings[];

int		_search_fheading ( char * );

static void	print_sdn(int, char *, SCALED);
static void	print_str(int, char *, char *);

/**
 ** wrform()
 **/

int
wrform(char *name, FORM *formp, int fd, int (*error_handler)( int , int , int ),
	int *which_set)
{
	int			fld;

	char *			cp;


	errno = 0;
	for (fld = 0; fld < FO_MAX; fld++)
	  if ((!which_set || which_set[fld]) &&
	      (formheadings[fld].infile || error_handler))
		switch (fld) {

#define HEAD	formheadings[fld].v

		case FO_PLEN:
			print_sdn(fd, HEAD, formp->plen);
			break;

		case FO_PWID:
			print_sdn(fd, HEAD, formp->pwid);
			break;

		case FO_LPI:
			print_sdn(fd, HEAD, formp->lpi);
			break;

		case FO_CPI:
			if (formp->cpi.val == N_COMPRESSED)
				print_str(fd, HEAD, NAME_COMPRESSED);
			else
				print_sdn(fd, HEAD, formp->cpi);
			break;

		case FO_NP:
			fdprintf(fd, "%s %d\n", HEAD, formp->np);
			break;

		case FO_CHSET:
			fdprintf(fd, "%s %s", HEAD, formp->chset);
			if (formp->mandatory == 1)
				fdprintf(fd, ",%s", MANSTR);
			fdprintf(fd, "\n");
			break;

		case FO_RCOLOR:
			print_str(fd, HEAD, formp->rcolor);
			break;

		case FO_CMT:
			if ((cp = formp->comment) && *cp) {
				fdprintf(fd, "%s\n", HEAD);
				do {
					char *	nl = strchr(cp, '\n');

					if (nl)
						*nl = 0;
					if (_search_fheading(cp) < FO_MAX)
						fdputc ('>', fd);
					fdprintf(fd, "%s\n", cp);
					if (nl)
						*nl = '\n';
					cp = nl;
				} while (cp++);	/* NOT *cp++ */
			}
			break;

		case FO_ALIGN:
			  /* this must always be the last field in the file
				  it is done outside of this loop */
			break;

		case FO_PAPER:
			if (formp->paper) {
				fdprintf(fd, "%s %s", HEAD, formp->paper);
				if (formp->isDefault == 1)
					fdprintf(fd, ",%s", DFTSTR);
				fdprintf(fd, "\n");
			}
			break;

		}

	if ((!which_set || which_set[FO_ALIGN]) &&
	    (formheadings[FO_ALIGN].infile || error_handler)) {
		  print_str(fd, formheadings[FO_ALIGN].v, formp->conttype);
			/*
			 * Actual alignment pattern has to be written
			 * out by caller; we leave the file pointer ready.
			 */
	}

	if (errno != 0)
		return (-1);

	/*
	 * Write out comment to a separate file (?)
	 */
	if (!error_handler) {

		char *			path;


		if (!(path = getformfile(name, COMMENT)))
			return (-1);

		if (formp->comment) {
			if (dumpstring(path, formp->comment) == -1) {
				Free (path);
				return (-1);
			}

		} else
			Unlink (path);

		Free (path);

	}

	return (0);
}

/**
 ** print_sdn() - PRINT SCALED DECIMAL NUMBER WITH HEADER
 ** print_str() - PRINT STRING WITH HEADER
 **/

static void
print_sdn(int fd, char *head, SCALED sdn)
{
	if (sdn.val <= 0)
		return;

	(void)fdprintf(fd, "%s ", head);
	fdprintsdn(fd, sdn);

	return;
}

static void
print_str(int fd, char *head, char *str)
{
	if (!str || !*str)
		return;

	(void)fdprintf(fd, "%s %s\n", head, str);

	return;
}
