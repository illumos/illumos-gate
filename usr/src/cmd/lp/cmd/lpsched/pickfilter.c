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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2.1.5	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"
#include "limits.h"

#include "lpsched.h"

#include "validate.h"

/*
 * Transform consecutive "LP_SEP" characters to a single comma and n-1 LP_SEP;
 *
 * BUT we'll leave LP_SEP inside single quotes alone!
 *
 * This is to allow the following case (and the like) to work correctly:
 *	prtitle='standard input'
 */

void
transform_WS_to_SEP(char *cp)
{	char *p;
	int inside_quote = 0;
	int done_one_already = 0;

	for (p = cp; *p != '\0'; p++) {
		if (*p == '\'') {
			inside_quote = (inside_quote + 1) % 2;
			continue;
		}
		if (inside_quote)
			continue;
		if (*p == ' ') {
			if (!done_one_already) {
				*p = ',';
				done_one_already = 1;
			} else {
				/* multiple LP_WS into one LP_SEP */
			}
		} else {
			done_one_already = 0;
		}
	}
}

/**
 ** pickfilter() - SEE IF WE CAN FIND A FILTER FOR THIS REQUEST
 **/

int
pickfilter(RSTATUS *prs, CANDIDATE *pc, FSTATUS *pfs)
{
	register char **	pp;
	register char **	pl;

	register PSTATUS *	pps		= pc->pps;

	char *			pipes[2]	= { 0 , 0 };
	char *			cp;
	char *			output_type;

	char **			modes		= 0;
	char **			parms		= 0;
	char **			valid_printer_types;
	char **			p_cpi		= 0;
	char **			p_lpi		= 0;
	char **			p_pwid		= 0;
	char **			p_plen		= 0;

	FILTERTYPE		ret		= fl_none;

	int			got_cpi		= 0;
	int			got_lpi		= 0;
	int			got_plen	= 0;
	int			got_pwid	= 0;
	int			must_have_filter= 0;

	unsigned long		chk;


	/* fix for bugid 1097387	*/
	output_type = (char *) NULL;

	/*
	 * The bulk of the code below is building a parameter list "parms"
	 * to send to "insfilter()".
	 */

	if (prs->request->modes) {
		cp = Strdup(prs->request->modes);
		transform_WS_to_SEP(cp);
		modes = getlist(cp, "", LP_SEP);
		Free (cp);
	}

	pp = parms = (char **)Malloc(
		2 * (NPARM_SPEC + lenlist(modes) + 1) * sizeof(char *)
	);

	/*
	 * Add to the parameter list the appropriate cpi/lpi/etc.
	 * characteristics (aka ``stuff'') that will be used for
	 * this job. The printer defaults are questionable.
	 * Take this opportunity to also save the ``stuff'' in
	 * the request structure.
	 */

	unload_str (&(prs->cpi));
	unload_str (&(prs->lpi));
	unload_str (&(prs->plen));
	unload_str (&(prs->pwid));

	/*
	 * If a form is involved, pick up its page size and print
	 * spacing requirements.
	 */
	if (pfs) {
		if (pfs->cpi) {
			*pp++ = PARM_CPI;
			*pp++ = prs->cpi = pfs->cpi;
			got_cpi = 1;
		}
		if (pfs->lpi) {
			*pp++ = PARM_LPI;
			*pp++ = prs->lpi = pfs->lpi;
			got_lpi = 1;
		}
		if (pfs->plen) {
			*pp++ = PARM_LENGTH;
			*pp++ = prs->plen = pfs->plen;
			got_plen = 1;
		}
		if (pfs->pwid) {
			*pp++ = PARM_WIDTH;
			*pp++ = prs->pwid = pfs->pwid;
			got_pwid = 1;
		}

	/*
	 * If no form is involved, pick up whatever page size and print
	 * spacing requirements were given by the user.
	 */
	} else {
		if (o_cpi) {
			*pp++ = PARM_CPI;
			*pp++ = prs->cpi = o_cpi;
			got_cpi = 1;
		}
		if (o_lpi) {
			*pp++ = PARM_LPI;
			*pp++ = prs->lpi = o_lpi;
			got_lpi = 1;
		}
		if (o_length) {
			*pp++ = PARM_LENGTH;
			*pp++ = prs->plen = o_length;
			got_plen = 1;
		}
		if (o_width) {
			*pp++ = PARM_WIDTH;
			*pp++ = prs->pwid = o_width;
			got_pwid = 1;
		}
	}

	/*
	 * Pick up whatever page size and print spacing requirements
	 * haven't been specified yet from the printer defaults.
	 *
	 * Note: The following cpi/lpi/etc are guaranteed to work
	 * for at least one type of the printer at hand, but not
	 * necessarily all types. Once we pick a type that works
	 * we'll verify that the cpi/lpi/etc stuff works, too.
	 * The code that does that assumes that we do the following last,
	 * after picking up the form and/or user stuff. If this changes,
	 * then the later code will have to be changed, too.
	 */
	if (!got_cpi && pps->cpi) {
		*pp++ = PARM_CPI;
		*(p_cpi = pp++) = prs->cpi = pps->cpi;
	}
	if (!got_lpi && pps->lpi) {
		*pp++ = PARM_LPI;
		*(p_lpi = pp++) = prs->lpi = pps->lpi;
	}
	if (!got_plen && pps->plen) {
		*pp++ = PARM_LENGTH;
		*(p_plen = pp++) = prs->plen = pps->plen;
	}
	if (!got_pwid && pps->pwid) {
		*pp++ = PARM_WIDTH;
		*(p_pwid = pp++) = prs->pwid = pps->pwid;
	}

	/*
	 * Pick up the number of pages, character set (the form's
	 * or the user's), the form name, the number of copies,
	 * and the modes.
	 */

	if (prs->request->pages) {
		*pp++ = PARM_PAGES;
		*pp++ = prs->request->pages;
		must_have_filter = 1;
	}

	if (prs->request->charset) {
		*pp++ = PARM_CHARSET;
		*pp++ = prs->request->charset;

	} else if (pfs && pfs->form->chset) {
		*pp++ = PARM_CHARSET;
		*pp++ = pfs->form->chset;
	}

	if (prs->request->form) {
		*pp++ = PARM_FORM;
		*pp++ = prs->request->form;
	}

	if (prs->request->copies > 1) {
		*pp++ = PARM_COPIES;
		sprintf ((*pp++ = BIGGEST_NUMBER_S), "%d", prs->request->copies);
	}

	if (modes) {
		for (pl = modes; *pl; pl++) {
			*pp++ = PARM_MODES;
			*pp++ = *pl;
		}
		must_have_filter = 1;
	}

	*pp = 0;	/* null terminated list! */


	/*
	 * If the printer type(s) are not ``unknown'', then include
	 * them as possible ``output'' type(s) to match
	 * with the user's input type (directly, or through a filter).
	 */
	if (!STREQU(*(pps->printer->printer_types), NAME_UNKNOWN))
		valid_printer_types = pc->printer_types;
	else {
		valid_printer_types = 0;
		must_have_filter = 0;
	}

	pc->fast = 0;
	pc->slow = 0;
	pc->output_type = 0;
	pc->flags = 0;
	ret = fl_none;

	/*
	 * If we don't really need a filter and the types match,
	 * then that's good enough. Some ``broadly defined''
	 * filters might match our needs, but if the printer
	 * can do what we need, then why pull in a filter?



	 * Besides, Section 3.40 in the requirements imply
	 * that we don't use a filter if the printer can handle
	 * the file.
	 */
	if (!must_have_filter ) {

		if (
			valid_printer_types
		     && searchlist_with_terminfo(
				prs->request->input_type,
				valid_printer_types
			)
		) {
			ret = fl_both;	/* not really, but ok */
			pc->printer_type = Strdup(prs->request->input_type);

		} else if (
			pps->printer->input_types
		     && searchlist_with_terminfo(
				prs->request->input_type,
				pps->printer->input_types
			)
		) {
			ret = fl_both;	/* not really, but ok */

			/*
			 * (1) There is one printer type, might even
			 *     be ``unknown'';
			 * (2) There are several printer types, but that
			 *     means only one input type, ``simple'',
			 *     which any of the printer types can handle.
			 */
			pc->printer_type = Strdup(*(pc->printer_types));

		}
	}

	/*
	 * Don't try using a filter if the user doesn't want
	 * a filter to be used! They would rather see an
	 * error message than (heaven forbid!) a filter being
	 * used.
	 */
	if (ret == fl_none && !(prs->request->actions & ACT_RAW)) {

		/*
		 * For each printer type, and each input type the printer
		 * accepts, see if we have a filter that matches the
		 * request to the printer. Each time we try, save the
		 * output type we use in case of success; we just might
		 * need that value later....
		 */

		for (
			pl = valid_printer_types;
			pl && *pl && ret == fl_none;
			pl++
		)
			ret = insfilter(
				pipes,
				prs->request->input_type,
				(output_type = *pl),
				*pl,
				pps->printer->name,
				parms,
				&(pc->flags)
			);
		if (ret != fl_none)
			pc->printer_type = Strdup(*pl);

		for (
			pl = pps->printer->input_types;
			pl && *pl && ret == fl_none;
			pl++
		)
			/*
			 * Don't waste time with check we've already made.
			 */
			if ((must_have_filter == 1) ||
				!valid_printer_types
			     || !searchlist(*pl, valid_printer_types)
			)
				/*
				 * Either we have one (or less) printer
				 * types and many input types, or we have
				 * one input type, ``simple''; regardless,
				 * using the first printer type is OK.
				 */
				ret = insfilter(
					pipes,
					prs->request->input_type,
					(output_type = *pl),
					*(pc->printer_types),
					pps->printer->name,
					parms,
					&(pc->flags)
				);
		if (ret != fl_none)
			pc->printer_type = Strdup(*(pc->printer_types));

	}

	/*
	 * If we were successful, check that the printer type
	 * we picked can handle the PRINTER'S cpi/lpi/etc. defaults.
	 * (We know that ALL the printer's types can handle the stuff
	 * the user gave or the stuff in the form.)
	 * Each printer's default that doesn't pass muster gets dropped.
	 * This may mean re-instantiating the filter(s) (if any).
	 */
	if (ret != fl_none && (p_cpi || p_lpi || p_pwid || p_plen)) {

#define	NZ(X)	((X)? *(X) : (char *)0)
		chk = chkprinter(
			pc->printer_type,
			NZ(p_cpi),
			NZ(p_lpi),
			NZ(p_plen),
			NZ(p_pwid),
			(char *)0
		);

		if (chk) {
			register char **	_pp;

			char *			hole	= "";


			/*
			 * Remove the offending printer defaults from the
			 * request list of cpi/lpi/etc. stuff, and punch
			 * (non-null!) holes in the parameter list.
			 */
#define DROP(P,R)	if (P) {P[-1] = P[0] = hole; R = 0;} else/*EMPTY*/
			if (chk & PCK_CPI)	DROP (p_cpi, prs->cpi);
			if (chk & PCK_LPI)	DROP (p_lpi, prs->lpi);
			if (chk & PCK_WIDTH)	DROP (p_pwid, prs->pwid);
			if (chk & PCK_LENGTH)	DROP (p_plen, prs->plen);

			/*
			 * If there are filters, we have to re-instantiate
			 * them. (Can't check "ret" here, because it may
			 * be misleading.)
			 */
			if (pipes[0] || pipes[1]) {

				/*
				 * First, close up the gaps we punched in
				 * the parameter list.
				 */
				for (pp = _pp = parms; *pp; pp++)
					if (*pp != hole)
						*_pp++ = *pp;
				*_pp = 0;

				/*
				 * Re-instantiate the filter(s). This
				 * CAN'T fail, because it is not mandatory
				 * that filters handle cpi/lpi/etc. stuff.
				 */
				ret = insfilter(
					pipes,
					prs->request->input_type,
					output_type,
					pc->printer_type,
					pps->printer->name,
					parms,
					&(pc->flags)
				);
			}
		}
	}

	/*
	 * Save the filters, if any. Note: although "ret" can be
	 * misleading, i.e. set to "fl_both" when there really aren't
	 * any filters, the declaration of "pipes" ensured they'd be
	 * zero if not set.
	 */
	if (ret == fl_both || ret == fl_slow)
		pc->slow = pipes[0];
	if (ret == fl_both || ret == fl_fast)
		pc->fast = pipes[1];

	if (ret != fl_none)
		pc->output_type = Strdup (output_type);

	/*
	 * Wait until now to allocate storage for the cpi/etc.
	 * stuff, to make life easier above.
	 */
	if (prs->cpi)	prs->cpi = Strdup(prs->cpi);
	if (prs->lpi)	prs->lpi = Strdup(prs->lpi);
	if (prs->plen)	prs->plen = Strdup(prs->plen);
	if (prs->pwid)	prs->pwid = Strdup(prs->pwid);


	if (parms)
		Free ((char *)parms);
	if (modes)
		freelist (modes);

	return ((ret != fl_none));
}
