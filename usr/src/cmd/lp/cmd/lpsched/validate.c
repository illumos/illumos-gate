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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* SVr4.0 1.11.1.10	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "lpsched.h"

#include "validate.h"

#include <syslog.h>
#include <errno.h>
#include <deflt.h>
#include <tsol/label.h>
#include <auth_list.h>

#define register auto


int		pickfilter ( RSTATUS * , CANDIDATE * , FSTATUS * );

unsigned long		chkprinter_result	= 0;
char *			o_cpi		= 0;
char *			o_lpi		= 0;
char *			o_width		= 0;
char *			o_length	= 0;

static int		wants_nobanner	= 0;
static int		wants_nolabels	= 0;
static int		lp_or_root	= 0;

static int		_chkopts ( RSTATUS *, CANDIDATE * , FSTATUS * );
static void		free_candidate ( CANDIDATE * );
static int		tsol_check_printer_label_range(char *, const char *);
static int		tsol_lpauth(char *, char *);
static int		secpolicy_chkpolicy(char *policyp);

/**
 ** _validate() - FIND A PRINTER TO HANDLE A REQUEST
 **/

short
_validate(RSTATUS *prs, PSTATUS *pps, PSTATUS *stop_pps, char **prefixp,
	 int moving)
{
	register CANDIDATE	*pc		= 0,
				*pcend,
				*best_pc	= 0;

	register FSTATUS	*pfs		= 0;

	register CLSTATUS	*pcs		= 0;

	CANDIDATE		*arena		= 0,
				single;

	size_t			n;
	int i;

	short			ret;

	chkprinter_result = 0;
	o_cpi = o_lpi = o_width = o_length = 0;
	wants_nobanner = 0;
	memset (&single, 0, sizeof(single));

	wants_nolabels = 0;
	/*
	 * If the system is labeled, the printing of postscript files
	 * is restricted.  All users can print postscript files if the
	 * file /etc/default/print contains "PRINT_POSTSCRIPT=1".
	 * (this is checked by secpolicy_chkpolicy).  Otherwise the
	 * user must have PRINT_POSTSCRIPT_AUTH to print postscript files.
	 */
	if ((is_system_labeled() &&
	    strcmp(prs->request->input_type, "postscript") == 0) &&
	    (secpolicy_chkpolicy("PRINT_POSTSCRIPT=") == 0)) {
		if (tsol_lpauth(PRINT_POSTSCRIPT_AUTH, prs->secure->user)
		    == 0) {
			ret = MDENYDEST;
			goto Return;
		}
	}
	lp_or_root = 0;

	if (bangequ(prs->secure->user, "root") ||
	    bangequ(prs->secure->user, "lp"))
			lp_or_root = 1;

	if (prefixp)
		*prefixp = prs->request->destination;

	/*
	 * If a destination other than "any" was given,
	 * see if it exists in our internal tables.
	 */
	if (!pps && prs->request->destination &&
	    !STREQU(prs->request->destination, NAME_ANY))
		if (((pps = search_pstatus(prs->request->destination)) != NULL) ||
		    ((pcs = search_cstatus(prs->request->destination)) != NULL) &&
		    pcs->class->members)
			/*EMPTY*/;
		else {
			ret = MNODEST;
			goto Return;
		}

	/*
	 * If we are trying to avoid a printer, but the request
	 * was destined for just that printer, we're out.
	 */
	if (pps && pps == stop_pps) {
		ret = MERRDEST;
		goto Return;
	}

	/*
	 * If a form was given, see if it exists; if so,
	 * see if the user is allowed to use it.
	 * If a remote printer was specified, then don't use any local
	 * form knowledge.
	 */
	if (prs && prs->request && prs->request->form && (pps || pcs)) {
		if ((pfs = search_fstatus(prs->request->form))) {
			if (lp_or_root || allowed(prs->secure->user,
				pfs->users_allowed, pfs->users_denied))
				/*EMPTY*/;
			else {
				ret = MDENYMEDIA;
				goto Return;
			}
		} else {
			ret = MNOMEDIA;
			goto Return;
		}
	}

	/*
	 * If the request includes -o options there may be pitch and
	 * size and no-banner requests that have to be checked. One
	 * could argue that this shouldn't be in the Spooler, because
	 * the Spooler's job is SPOOLING, not PRINTING. That's right,
	 * except that the Spooler will be making a choice of printers
	 * so it has to evaluate carefully: E.g. user wants ANY printer,
	 * so we should pick one that can handle what he/she wants.
	 * 
	 * Parse out the important stuff here so we have it when we
	 * need it. 
	 */
	{
		register char		**list,
					**pl;

		if (
			prs->request->options
		     && (list = dashos(prs->request->options))
		) {
			for (pl = list ; *pl; pl++)
				if (STRNEQU(*pl, "cpi=", 4))
					o_cpi = Strdup(*pl + 4);
				else if (STRNEQU(*pl, "lpi=", 4))
					o_lpi = Strdup(*pl + 4);
				else if (STRNEQU(*pl, "width=", 6))
					o_width = Strdup(*pl + 6);
				else if (STRNEQU(*pl, "length=", 7))
					o_length = Strdup(*pl + 7);
				else if (STREQU(*pl, "nobanner"))
					wants_nobanner = 1;
				else if (STREQU(*pl, "nolabels"))
					wants_nolabels = 1;
			freelist (list);
		}
	}

	/*
	 * This macro checks that a form has a mandatory print wheel
	 * (or character set).
	 */
#define	CHKMAND(PFS) \
	( \
		(PFS) \
	     && (PFS)->form->chset \
	     && !STREQU((PFS)->form->chset, NAME_ANY) \
	     && (PFS)->form->mandatory \
	)

	/*
	 * This macro checks that the user is allowed to use the
	 * printer.
	 */
#define CHKU(PRS,PPS) \
	( \
		lp_or_root \
	     || allowed( \
			(PRS)->secure->user, \
			(PPS)->users_allowed, \
			(PPS)->users_denied \
		) \
	)

	/*
	 * This macro checks that the form is allowed on the printer,
	 * or is already mounted there.
	 * Note: By doing this check we don't have to check that the
	 * characteristics of the form, such as pitch, size, or
	 * character set, against the printer's capabilities, ASSUMING,
	 * of course, that the allow list is correct. That is, the
	 * allow list lists forms that have already been checked against
	 * the printer!
	 */
#define CHKF(PFS,PPS) \
	( \
		isFormMountedOnPrinter(PPS,PFS) \
	     || allowed( \
			(PFS)->form->name, \
			(PPS)->forms_allowed, \
			(PPS)->forms_denied \
		) \
	)

	/*
	 * This macro checks that the print wheel is acceptable
	 * for the printer or is mounted. Note: If the printer doesn't
	 * take print wheels, the check passes. The check for printers
	 * that don't take print wheels is below.
	 */
#define CHKPW(PW,PPS) \
	( \
		!(PPS)->printer->daisy \
	     || ( \
			(PPS)->pwheel_name \
		     && STREQU((PPS)->pwheel_name, (PW)) \
		) \
	     || searchlist((PW), (PPS)->printer->char_sets) \
	)

	/*
	 * This macro checks the pitch, page size, and (if need be)
	 * the character set. The character set isn't checked if the
	 * printer takes print wheels, or if the character set is
	 * listed in the printer's alias list.
	 * The form has to be checked as well; while we're sure that
	 * at least one type for each printer can handle the form's
	 * cpi/lpi/etc. characteristics (lpadmin made sure), we aren't
	 * sure that ALL the types work.
	 */
#define CHKOPTS(PRS,PC,PFS) _chkopts((PRS),(PC),(PFS)) /* was a macro */

	/*
	 * This macro checks the acceptance status of a printer.
	 * If the request is already assigned to that printer,
	 * then it's okay. It's ambiguous what should happen if
	 * originally a "-d any" request was accepted, temporarily
	 * assigned one printer, then the administrator (1) rejected
	 * further requests for the printers and (2) made the
	 * temporarily assigned printer unusable for the request.
	 * What will happen, of course, is that the request will
	 * be canceled, even though the other printers would be okay
	 * if not rejecting....but if we were to say, gee it's okay,
	 * the request has already been accepted, we may be allowing
	 * it on printers that were NEVER accepting. Thus we can
	 * continue to accept it only for the printer already assigned.
	 */
#define CHKACCEPT(PRS,PPS) \
	( \
		!((PPS)->status & PS_REJECTED) \
	     || (PRS)->printer == (PPS) \
	     || moving \
	)

	/*
	 * If a print wheel or character set is given, see if it
	 * is allowed on the form.
	 */
	if (prs->request->charset)
		if (
			!CHKMAND(pfs)
		     || STREQU(prs->request->charset, pfs->form->chset)
		)
			/*EMPTY*/;
		else {
			ret = MDENYMEDIA;
			chkprinter_result |= PCK_CHARSET;
			goto Return;
		}

	/*
	 * If a single printer was named, check the request against it.
	 * Do the accept/reject check late so that we give the most
	 * useful information to the user.
	 */
	if (pps) {
		(pc = &single)->pps = pps;

		/* Does the printer allow the user? */
		if (!CHKU(prs, pps)) {
			ret = MDENYDEST;
			goto Return;
		}

		/* Check printer label range */
		if (is_system_labeled() && prs->secure->slabel != NULL) {
			if (tsol_check_printer_label_range(
			    prs->secure->slabel,
			    pps->printer->name) == 0) {
				ret = MDENYDEST;
				goto Return;
			}
		}

		/* Does the printer allow the form? */
		if (pfs && !CHKF(pfs, pps)) {
			ret = MNOMOUNT;
			goto Return;
		}

		/* Does the printer allow the pwheel? */
		if (
			prs->request->charset
		     && !CHKPW(prs->request->charset, pps)
		) {
			ret = MNOMOUNT;
			goto Return;
		}

		/* Can printer handle the pitch/size/charset/nobanner? */
		if (!CHKOPTS(prs, pc, pfs)) {
			ret = MDENYDEST;
			goto Return;
		}

		/* Is the printer allowing requests? */
		if (!CHKACCEPT(prs, pps)) {
			ret = MERRDEST;
			goto Return;
		}

		/* Is there a filter which will convert the input? */
		if (!pickfilter(prs, pc, pfs)) {
			ret = MNOFILTER;
			goto Return;
		}

		best_pc = pc;
		ret = MOK;
		goto Return;
	}

	/*
	 * Do the acceptance check on the class (if we have one)
	 * now so we can proceed with checks on individual printers
	 * in the class. Don't toss out the request if it is already
	 * assigned a printer just because the class is NOW rejecting.
	 */
	if (
		pcs
	     && (pcs->status & CS_REJECTED)
	     && !moving
	     && !prs->printer
	) {
		ret = MERRDEST;
		goto Return;
	}

	/*
	 * Construct a list of printers based on the destination
	 * given. Cross off those that aren't accepting requests,
	 * that can't take the form, or which the user can't use.
	 * See if the list becomes empty.
	 */

	if (pcs)
		n = lenlist(pcs->class->members);
	else {
		for (n = 0; PStatus != NULL && PStatus[n] != NULL; n++) ;
	}
	pcend = arena = (CANDIDATE *)Calloc(n, sizeof(CANDIDATE));

	/*
	 * Start with a list of printers that are accepting requests.
	 * Don't skip a printer if it's rejecting but the request
	 * has already been accepted for it.
	 */
	if (pcs) {
		register char		 **pn;

		for (pn = pcs->class->members; *pn; pn++)
			if (
				((pps = search_pstatus(*pn)) != NULL)
			     && pps != stop_pps
			)
				(pcend++)->pps = pps;


	} else
		for (i = 0; PStatus != NULL && PStatus[i] != NULL; i++) {
			pps = PStatus[i];

			if (CHKACCEPT(prs, pps) && pps != stop_pps)
				(pcend++)->pps = pps;
		}

	if (pcend == arena) {
		ret = MERRDEST;
		goto Return;
	}

	/*
	 * Clean out printers that the user can't use. We piggy-back
	 * the pitch/size/banner checks here because the same error return
	 * is given (strange, eh?).
	 */
	{
		register CANDIDATE	*pcend2;

		for (pcend2 = pc = arena; pc < pcend; pc++) {
			if (CHKU(prs, pc->pps) && CHKOPTS(prs, pc, pfs))
				*pcend2++ = *pc;
			else
				free_candidate (pc);
		}

		if (pcend2 == arena) {
			ret = MDENYDEST;
			goto Return;
		}
		pcend = pcend2;

	}

	/*
	 * Clean out printers that can't mount the form,
	 * EXCEPT for printers that already have it mounted:
	 */
	if (pfs) {
		register CANDIDATE	*pcend2;

		for (pcend2 = pc = arena; pc < pcend; pc++)
			if (CHKF(pfs, pc->pps))
				*pcend2++ = *pc;
			else
				free_candidate (pc);

		if (pcend2 == arena) {
			ret = MNOMOUNT;
			goto Return;
		}
		pcend = pcend2;

	}

	/*
	 * Clean out printers that can't take the print wheel
	 * EXCEPT for printers that already have it mounted
	 * or printers for which it is a selectable character set:
	 */
	if (prs->request->charset) {
		register CANDIDATE	*pcend2;

		for (pcend2 = pc = arena; pc < pcend; pc++)
			if (CHKPW(prs->request->charset, pc->pps))
				*pcend2++ = *pc;
			else
				free_candidate (pc);

		if (pcend2 == arena) {
			ret = MNOMOUNT;
			goto Return;
		}
		pcend = pcend2;

	}

	/*
	 * Clean out printers that can't handle the printing
	 * and for which there's no filter to convert the input.
	 *
	 */

	/*
	 * Is the form mounted, or is none needed?
	 */
#define CHKFMNT(PFS,PPS) (isFormUsableOnPrinter(PPS,PFS))

	/*
	 * Is the print-wheel mounted, or is none needed?
	 */
#define CHKPWMNT(PRS,PPS) SAME((PPS)->pwheel_name, (PRS)->request->charset)

	/*
	 * Do we NOT need a special character set, or can we select
	 * it on the printer? Note: Getting this far means that IF
	 * the printer has selectable character sets (!daisy) then
	 * it can select the one we want.
	 */
#define CHKCHSET(PRS,PPS) \
	( \
		!(PRS)->request->charset \
	     || !(PPS)->printer->daisy \
	)

	/*
	 * Is the printer able to print now?
	 */
#define CHKENB(PPS)	 (!((PPS)->status & (PS_DISABLED|PS_FAULTED)))

	/*
	 * Is the printer not busy printing another request, or
	 * not awaiting an auto-retry after a fault?
	 */
#define CHKFREE(PPS)	 (!((PPS)->status & (PS_BUSY|PS_LATER)))

	{
		register CANDIDATE	*pcend2;

		for (pcend2 = pc = arena; pc < pcend; pc++)
			if (pickfilter(prs, pc, pfs)) {

				/*
				 * Compute a ``weight'' for this printer,
				 * based on its status. We'll later pick
				 * the printer with the highest weight.
				 */
				pc->weight = 0;
				if (!pc->fast && !pc->slow)
					pc->weight += WEIGHT_NOFILTER;
				if (CHKFREE(pc->pps))
					pc->weight += WEIGHT_FREE;
				if (CHKENB(pc->pps))
					pc->weight += WEIGHT_ENABLED;
				if (CHKFMNT(pfs, pc->pps))
					pc->weight += WEIGHT_MOUNTED;
				if (CHKPWMNT(prs, pc->pps))
					pc->weight += WEIGHT_MOUNTED;
				if (CHKCHSET(prs, pc->pps))
					pc->weight += WEIGHT_SELECTS;

#if	defined(FILTER_EARLY_OUT)
				if (pc->weight == WEIGHT_MAX) {
					/*
					 * This is the one!
					 */
					best_pc = pc;
					ret = MOK;
					goto Return;
				}
#endif
				/*
				 * This is a candidate!
				 */
				*pcend2++ = *pc;

			} else
				/*
				 * No filter for this one!
				 */
				free_candidate (pc);

		if (pcend2 == arena) {
			ret = MNOFILTER;
			goto Return;
		}
		pcend = pcend2;

	}

	if (pcend - arena == 1) {
		best_pc = arena;
		ret = MOK;
		goto Return;
	}
	/*
	 * Clean out local printers
	 * where the request is outside the printer label range.
	 */
	{
		register CANDIDATE	*pcend2 = pcend;

		if (is_system_labeled()) {
			for (pcend2 = pc = arena; pc < pcend; pc++) {
				if (tsol_check_printer_label_range(
				    prs->secure->slabel,
				    pps->printer->name) == 1)
					*pcend2++ = *pc;
				else
					free_candidate(pc);
			}
		}

		if (pcend2 == arena) {
			ret = MDENYDEST;
			goto Return;
		}
		pcend = pcend2;
	}

#if	defined(OTHER_FACTORS)
	/*
	 * Here you might want to add code that considers
	 * other factors: the size of the file(s) to be
	 * printed ("prs->secure->size") in relation to the
	 * printer (e.g. printer A gets mostly large
	 * files, printer B gets mostly small files); the
	 * number/total-size of requests currently queued
	 * for the printer; etc.
	 *
	 * If your code includes eliminating printers drop them
	 * from the list (as done in several places above).
	 * Otherwise, your code should add weights to the weight
	 * already computed. Change the WEIGHT_MAX, increase the
	 * other WEIGHT_X values to compensate, etc., as appropriate.
	 */
	;
#endif

	/*
	 * Pick the best printer from a list of eligible candidates.
	 */
	best_pc = arena;
	for (pc = arena + 1; pc < pcend; pc++)
		if (pc->weight > best_pc->weight)
			best_pc = pc;
	ret = MOK;

	/*
	 * Branch to here if MOK and/or if things have been allocated.
	 */
Return:	if (ret == MOK) {
		register USER		*pu = Getuser(prs->secure->user);

		register char		*pwheel_name;

		PSTATUS			*oldpps = prs->printer;


		/*
		 * We are going to accept this print request, having
		 * found a printer for it. This printer will be assigned
		 * to the request, although this assignment may be
		 * temporary if other printers qualify and this printer
		 * is changed to no longer qualify. Qualification in
		 * this context includes being ready to print!
		 */
		prs->printer = best_pc->pps;
		load_str (&(prs->printer_type), best_pc->printer_type);

		/*
		 * Assign the form (if any) to the request. Adjust
		 * the number of requests queued for old and new form
		 * accordingly.
		 */
		if (prs->form != pfs) {
			unqueue_form (prs);
			queue_form (prs, pfs);
		}

		/*
		 * Ditto for the print wheel, except include here the
		 * print wheel needed by the form.
		 * CAUTION: When checking this request later, don't
		 * refuse to service it if the print wheel for the
		 * form isn't mounted but the form is; a mounted form
		 * overrides its other needs. Don't be confused by the
		 * name of the bit, RSS_PWMAND; a printer that prints
		 * this request MUST have the print wheel mounted
		 * (if it takes print wheels) if the user asked for
		 * a particular print wheel.
		 */
		prs->status &= ~RSS_PWMAND;
		if (CHKMAND(pfs))
			pwheel_name = pfs->form->chset;
		else
			if ((pwheel_name = prs->request->charset) != NULL)
				prs->status |= RSS_PWMAND;

		if (!SAME(pwheel_name, prs->pwheel_name)) {
			unqueue_pwheel (prs);
			queue_pwheel (prs, pwheel_name);
		}

		/*
		 * Adjust the priority to lie within the limits allowed
		 * for the user (this is a silent adjustment as required).
		 * CURRENTLY, ONLY NEW REQUESTS WILL GET QUEUED ACCORDING
		 * TO THIS PRIORITY. EXISTING REQUESTS BEING (RE)EVALUATED
		 * WILL NOT BE REQUEUED.
		 * A wild priority is changed to the default, or the
		 * limit, whichever is the lower priority (higher value).
		 */
		if (prs->request->priority < 0 || 39 < prs->request->priority)
			prs->request->priority = getdfltpri();
		if (pu && prs->request->priority < pu->priority_limit)
			prs->request->priority = pu->priority_limit;

		/*
		 * If a filter is involved, change the number of
		 * copies to 1 (if the filter handles it).
		 */
		if (
			(best_pc->fast || best_pc->slow)
		     && (best_pc->flags & FPARM_COPIES)
		     && prs->request->copies > 1
		)
			prs->copies = 1;
		else
			/*
			 * We use two ".copies" because we don't
			 * want to lose track of the number requested,
			 * but do want to mark the number the interface
			 * program is to handle. Here is the best
			 * place to know this.
			 */
			prs->copies = prs->request->copies;

		if (best_pc->slow) {
			/*
			 * If the filter has changed, the request will
			 * have to be refiltered. This may mean stopping
			 * a currently running filter or interface.
			 */
			if (!SAME(best_pc->slow, prs->slow)) {

			    if (prs->request->outcome & RS_FILTERED)
				prs->request->outcome &= ~RS_FILTERED;

			    if (
				prs->request->outcome & RS_FILTERING
			     && !(prs->request->outcome & RS_STOPPED)
			    ) {
				prs->request->outcome |= RS_REFILTER;
				prs->request->outcome |= RS_STOPPED;
				terminate (prs->exec);

			    } else if (
				prs->request->outcome & RS_PRINTING
			     && !(prs->request->outcome & RS_STOPPED)
			    ) {
				prs->request->outcome |= RS_STOPPED;
				terminate (oldpps->exec);
			    }

			}

			load_str (&(prs->slow), best_pc->slow);
			/* Assumption: if there is a slow filter,
			 * there is an output_type
			 */

			load_str (&(prs->output_type), best_pc->output_type);
		} else
			unload_str (&(prs->slow));

		load_str (&(prs->fast), best_pc->fast);

		if (prs->request->actions & ACT_FAST && prs->slow) {
			if (prs->fast) {
				prs->fast = makestr(
					prs->slow,
					"|",
					prs->fast,
					(char *)0
				);
				Free (prs->slow);
			} else
				prs->fast = prs->slow;
			prs->slow = 0;
		}

	}


	/*
	 * Free the space allocated for the candidates, INCLUDING
	 * the one chosen. Any allocated space in the chosen candidate
	 * that has to be saved should have been COPIED already.
	 */
	if (arena) {
		for (pc = arena; pc < pcend; pc++)
			free_candidate (pc);
		Free ((char *)arena);
	} else if (best_pc)
		free_candidate (best_pc);

	if (o_length)
		Free (o_length);
	if (o_width)
		Free (o_width);
	if (o_lpi)
		Free (o_lpi);
	if (o_cpi)
		Free (o_cpi);


	/*
	 * The following value is valid ONLY IF the request
	 * is canceled or rejected. Not all requests that
	 * we fail in this routine are tossed out!
	 */
	prs->reason = ret;


	return (ret);
}

/**
 ** _chkopts() - CHECK -o OPTIONS
 **/

static int
_chkopts(RSTATUS *prs, CANDIDATE *pc, FSTATUS *pfs)
{
	unsigned long		ret	= 0;
	unsigned long		chk	= 0;

	char *			charset;
	char *			cpi	= 0;
	char *			lpi	= 0;
	char *			width	= 0;
	char *			length	= 0;
	char *			paper = NULL;

	char **			pt;
	int			nobanner_not_allowed = 0;


	/*
	 * If we have a form, it overrides whatever print characteristics
	 * the user gave.
	 */
	if (pfs) {
		cpi = pfs->cpi;
		lpi = pfs->lpi;
		width = pfs->pwid;
		length = pfs->plen;
		paper = pfs->form->paper;
	} else {
		cpi = o_cpi;
		lpi = o_lpi;
		width = o_width;
		length = o_length;
	}

	/*
	 * If the printer takes print wheels, or the character set
	 * the user wants is listed in the character set map for this
	 * printer, we needn't check if the printer can handle the
	 * character set. (Note: The check for the print wheel case
	 * is done elsewhere.)
	 */
		
	if (pc->pps->printer->daisy ||
	    search_cslist(prs->request->charset, pc->pps->printer->char_sets))
		charset = 0;
	else
		charset = prs->request->charset;

	pc->printer_types = 0;
	for (pt = pc->pps->printer->printer_types; *pt; pt++) {
		unsigned long		this;

		if (paper) {
			if (allowed(paper,pc->pps->paper_allowed,NULL)) {
				addlist (&(pc->printer_types), *pt);
			} else {
				ret |= PCK_PAPER;
			}
		} else {
			this = chkprinter(*pt, cpi, lpi, length, width,
				charset);
			if (this == 0)
				addlist(&(pc->printer_types), *pt);
			chk |= this;
		}
	}
	if (!pc->printer_types)
		ret |= chk;

	/*
	 * If the sytem is labeled, then user who wants 'nolabels' must
	 * have PRINT_UNLABELED_AUTH authorizations to allow it.
	 */
	if (is_system_labeled() && (wants_nolabels == 1)) {
		if (!tsol_lpauth(PRINT_UNLABELED_AUTH, prs->secure->user)) {
			/* if not authorized, remove "nolabels" from options */
			register char		**list;
			if (prs->request->options &&
			    (list = dashos(prs->request->options))) {
				dellist(&list, "nolabels");
				free(prs->request->options);
				prs->request->options = sprintlist(list);
			}
		}
	}


	if (pc->pps->printer->banner == BAN_ALWAYS) {
		/* delete "nobanner" */
		char **list;

		/*
		 * If the system is labeled, users must have
		 * PRINT_NOBANNER_AUTH authorization to print
		 * without a banner.
		 */
		if (is_system_labeled()) {
			if (wants_nobanner == 1) {
				if (tsol_lpauth(PRINT_NOBANNER_AUTH,
					prs->secure->user) == 0) {
					nobanner_not_allowed = 1;
				}
			}

		}
		else if ((wants_nobanner == 1) && (lp_or_root != 1)) {
			nobanner_not_allowed = 1;
		}
		if (nobanner_not_allowed == 1) {
			/* Take out 'nobanner' from request options. */
			if (prs->request->options &&
			    (list = dashos(prs->request->options))) {
				dellist(&list, "nobanner");
				free(prs->request->options);
				prs->request->options = sprintlist(list);
			}
		}
	} else if (pc->pps->printer->banner == BAN_NEVER) {
		if (wants_nobanner == 0) {
			/* add "nobanner" */
			char **list = NULL;

			if (prs->request->options) {
				list = dashos(prs->request->options);
				free(prs->request->options);
			}
			appendlist(&list, "nobanner");
			prs->request->options = sprintlist(list);
		}
	} else /* if (pc->pps->printer->banner == BAN_OPTIONAL) */ {
		/* it is optional, leave it alone */
	}

	chkprinter_result |= ret;
	return (ret == 0);
}

/**
 ** free_candidate()
 **/

static void
free_candidate(CANDIDATE *pc)
{
	if (pc->slow)
		unload_str (&(pc->slow));
	if (pc->fast)
		unload_str (&(pc->fast));
	if (pc->printer_types) {
		freelist (pc->printer_types);
		pc->printer_types = 0;
	}
	if (pc->printer_type)
		unload_str (&(pc->printer_type));
	if (pc->output_type)
		unload_str (&(pc->output_type));
	return;
}

static int
tsol_check_printer_label_range(char *slabel, const char *printer)
{
	int			in_range = 0;
	int			err = 0;
	m_range_t		*range;
	m_label_t	*sl = NULL;

	if (slabel == NULL)
		return (0);

	if ((err =
	    (str_to_label(slabel, &sl, USER_CLEAR, L_NO_CORRECTION, &in_range)))
	    == -1) {
		/* stobsl error on printer max label */
		return (0);
	}
	if ((range = getdevicerange(printer)) == NULL) {
		m_label_free(sl);
		return (0);
	}

	/* blinrange returns true (1) if in range, false (0) if not */
	in_range = blinrange(sl, range);

	m_label_free(sl);
	m_label_free(range->lower_bound);
	m_label_free(range->upper_bound);
	free(range);

	return (in_range);
}

/*
 * Given a character string with a "username" or "system!username"
 * this function returns a pointer to "username"
 */
static int
tsol_lpauth(char *auth, char *in_name)
{
	char *cp;
	int res;

	if ((cp = strchr(in_name, '@')) != NULL) {
		/* user@system */
		*cp = '\0';
		res = chkauthattr(auth, in_name);
		*cp = '@';
	} else if ((cp = strchr(in_name, '!')) != NULL)
		/* system!user */
		res = chkauthattr(auth, cp+1);
	else
		/* user */
		res = chkauthattr(auth, in_name);

	return (res);
}

#define	POLICY_FILE	"/etc/default/print"

int
secpolicy_chkpolicy(char *policyp)
{
	char *option;
	int opt_val;

	if (policyp == NULL)
		return (0);
	opt_val = 0;
	if (defopen(POLICY_FILE) == 0) {

		defcntl(DC_SETFLAGS, DC_STD & ~DC_CASE); /* ignore case */

		if ((option = defread(policyp)) != NULL)
			opt_val = atoi(option);
	}
	(void) defopen((char *)NULL);
	syslog(LOG_DEBUG, "--- Policy %s, opt_val==%d",
	    policyp ? policyp : "NULL", opt_val);
	return (opt_val);
}
