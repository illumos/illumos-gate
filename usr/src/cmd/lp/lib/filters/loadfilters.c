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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "stdlib.h"
#include "unistd.h"

#include "lp.h"
#include "filters.h"

_FILTER			*filters;

size_t			nfilters;

static int		getfields (int, char *[], char *, int, int, char *);
static int		fs_cmp(const void *, const void *);

/**
 ** loadfilters() - READ FILTERS FROM FILTER TABLE INTO INTERNAL STRUCTURE
 **/

int
loadfilters(char *file)
{
	register _FILTER	*pf;
	int fd;
	char			*filt[FL_MAX],
				buf[3 * BUFSIZ];
	size_t			nalloc;

	if (filters) {
		nalloc = nfilters;
		trash_filters ();
	} else
		nalloc = FL_MAX_GUESS;

	if ((fd = open_filtertable(file, "r")) < 0)
		return (-1);

	/*
	 * Preallocate space for the internal filter table.
	 * Our guess is the number of filters previously read in,
	 * if any have been read in before (see above).
	 */
	filters = (_FILTER *)Malloc((nalloc + 1) * sizeof(_FILTER));
	if (!filters) {
		close(fd);
		errno = ENOMEM;
		return (-1);
	}

	for (
		pf = filters, nfilters = 0;
		getfields(fd, filt, buf, sizeof(buf), FL_MAX, FL_SEP) != -1;
		pf++
	) {

		char			**list;

		/*
		 * Allocate more space if needed.
		 */
		if (++nfilters > nalloc) {
			nalloc = nfilters;
			filters = (_FILTER *)Realloc(
				filters,
				(nalloc + 1) * sizeof(_FILTER)
			);
			if (!filters) {
				close(fd);
				errno = ENOMEM;
				return (-1);
			}
			pf = &filters[nfilters - 1];
		}

#define DFLT(X)	(filt[X] && *filt[X]? filt[X] : NAME_ANY)

		pf->name = Strdup(filt[FL_NAME]);
		pf->type = s_to_filtertype(filt[FL_TYPE]);
		pf->command = Strdup(filt[FL_CMD]);

		pf->printers = getlist(DFLT(FL_PRTRS), LP_WS, LP_SEP);

		list = getlist(DFLT(FL_PTYPS), LP_WS, LP_SEP);
		pf->printer_types = sl_to_typel(list);
		freelist (list);

		list = getlist(DFLT(FL_ITYPS), LP_WS, LP_SEP);
		pf->input_types = sl_to_typel(list);
		freelist (list);

		list = getlist(DFLT(FL_OTYPS), LP_WS, LP_SEP);
		pf->output_types = sl_to_typel(list);
		freelist (list);

		/*
		 * Note the use of "" instead of LP_WS. The
		 * "sl_to_templatel()" routine will take care
		 * of stripping leading blanks. Stripping trailing
		 * blanks would be nice but shouldn't matter.
		 */

/* quote reason #3 (in "getlist()") */
		list = getlist(filt[FL_TMPS], "", LP_SEP);

/* quote reason #4 (in "s_to_template()") */
		pf->templates = sl_to_templatel(list);
		freelist (list);

	}
	if (errno != 0) {
		int			save_errno = errno;

		free_filter (pf);
		close(fd);
		errno = save_errno;
		return (-1);
	}
	close(fd);

	/*
	 * If we have more space allocated than we need,
	 * return the extra.
	 */
	if (nfilters != nalloc) {
		filters = (_FILTER *)Realloc(
			filters,
			(nfilters + 1) * sizeof(_FILTER)
		);
		if (!filters) {
			errno = ENOMEM;
			return (-1);
		}
	}
	filters[nfilters].name = 0;

	/*
	 * Sort the filters, putting ``fast'' filters before
	 * ``slow'' filters. This preps the list for "insfilter()"
	 * so that it can easily pick fast filters over otherwise
	 * equivalent slow filters. This sorting is done every
	 * time we read in the table; one might think that if
	 * "putfilter()" would insert in the correct order then
	 * the table, when written out to disk, would be sorted
	 * already--removing the need to sort it here. We don't
	 * take that approach, because (1) sorting it isn't that
	 * expensive and (2) someone might tamper with the table
	 * file.
	 */
	qsort ((char *)filters, nfilters, sizeof(_FILTER), fs_cmp);

	return (0);
}

/**
 ** getfields() - PARSE NON-COMMENT LINE FROM FILE INTO FIELDS
 **/

static int
getfields(int fd, char *fields[], char *buf, int bufsiz, int max, char *seps)
{
	register char		*p,
				*q;

	register int		n	= 0;
	enum ParsingMode {CHECK_LEAD_DBL_QUOTE, NORMAL_PARSING, LITERAL_READ} eMode;
	errno = 0;
	while (fdgets(buf, bufsiz, fd) != NULL) {
		buf[strlen(buf) - 1] = 0;
		p = buf + strspn(buf, " \t");
		if (*p && *p != '#') {
			for (eMode = CHECK_LEAD_DBL_QUOTE, fields[n++] = q = p; *p; ) {
				switch (eMode) {
				case CHECK_LEAD_DBL_QUOTE: /* check for leading double quote */
					if (*p == '"') {
						eMode = LITERAL_READ;
						p++;
						break;
					}
					eMode = NORMAL_PARSING;
					/* FALLTHROUGH */

				case NORMAL_PARSING: /* default legacy editing */
					if (*p == '\\') {
						if (
/* quote reason #1 */					p[1] == '\\'
/* quote reason #2 */				     || strchr(seps, p[1])
						)
							p++;
						*q++ = *p++;
					} else if (strchr(seps, *p)) {
						*q++ = 0;
						p++;
						if (n < max) {
							fields[n++] = q;
							eMode = CHECK_LEAD_DBL_QUOTE;
						}
					} else
						*q++ = *p++;
					break;

				case LITERAL_READ: /* read literally until another double quote */
					if (*p == '\\' && p[1] == '"') { /* embedded double quote */
						p++;
						*q++ = *p++;
					} else if (*p == '"') { /* end of literal read */
						p++;
						eMode = NORMAL_PARSING; 
					} else {
						*q++ = *p++; /* capture as is */
					}
					break;
				}
			}
			*q = 0;
			while (n < max)
				fields[n++] = "";
			return (n);
		}
	}
	return (-1);
}

/**
 ** fs_cmp() - COMPARE TWO FILTERS BY "FILTERTYPE"
 **/

static int
fs_cmp(const void *pfa, const void *pfb)
{
	if (((_FILTER *)pfa)->type == ((_FILTER *)pfb)->type)
		return (0);
	else if (((_FILTER *)pfa)->type == fl_fast)
		return (-1);
	else
		return (1);
}
