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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "assert.h"
#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"
#include "filters.h"

#include "regex.h"


#define	MATCH(PT, PM) (STREQU((PT)->pattern, PATT_STAR) || \
					match((PT)->re, *((PM)->pvalue)))


typedef struct PARM {
	char			*keyword;
	unsigned short		flags;
	char			**pvalue;
}			PARM;

#define	X_MUST	0x0800	/* Pipeline MUST use this parm */
#define	X_FIRST	0x1000	/* Use parm only in 1st cmd of pipeline */
#define	X_FIXED	0x2000	/* Get value from elsewhere, not parms */
#define	X_MANY	0x4000	/* Several values allowed for parm */
#define	X_USED	0x8000	/* Used already, don't use again */

static struct S {
	TYPE			input_type;
	TYPE			output_type;
	TYPE			printer_type;
	char			*printer;
	PARM			*parms;
} S;

#if	defined(__STDC__)

static int		searchlist_t(TYPE *, TYPE *);
static int		instantiate(_FILTER **, TYPE *, TYPE *,
							int (*)(), void *);
static int		check_pipeline(_FILTER *, PARM *);
static char		*build_pipe(_FILTER *, PARM *, unsigned short *);
#else

static int		searchlist_t();
static int		instantiate();
static int		check_pipeline();
static char		*build_pipe();

#endif

/*
 * Table of recognized keywords, with info. about them.
 */

#define	NFIXED 4

static PARM		parmtable[] = {

/* These must be the first NFIXED, and in this order */
PARM_INPUT,	X_FIXED,			&S.input_type.name,
PARM_OUTPUT,	X_FIXED,			&S.output_type.name,
PARM_TERM,	X_FIXED,			&S.printer_type.name,
PARM_PRINTER,	X_FIXED,			&S.printer,

PARM_CPI,	FPARM_CPI,			0,
PARM_LPI,	FPARM_LPI,			0,
PARM_LENGTH,	FPARM_LENGTH,			0,
PARM_WIDTH,	FPARM_WIDTH,			0,
PARM_PAGES,	FPARM_PAGES | X_FIRST | X_MUST,	0,
PARM_CHARSET,	FPARM_CHARSET,			0,
PARM_FORM,	FPARM_FORM,			0,
PARM_COPIES,	FPARM_COPIES | X_FIRST,		0,
PARM_MODES,	FPARM_MODES | X_MANY | X_MUST,	0,
0,		0,				0,
};

/*
 * insfilter()
 */

FILTERTYPE
#if	defined(__STDC__)
insfilter(
	char			**pipes,
	char			*input_type,
	char			*output_type,
	char			*printer_type,
	char			*printer,
	char			**parms,
	unsigned short		*flagsp
)
#else
insfilter(pipes, input_type, output_type, printer_type, printer, parms, flagsp)
	char			**pipes,
				*input_type,
				*output_type,
				*printer_type,
				*printer,
				**parms;
	unsigned short		*flagsp;
#endif
{
	_FILTER			*pipeline;

	FILTERTYPE		ret;


	S.input_type.name = input_type;
	S.input_type.info = isterminfo(input_type);
	S.output_type.name = output_type;
	S.output_type.info = isterminfo(output_type);
	S.printer_type.name = printer_type;
	S.printer_type.info = isterminfo(printer_type);
	S.printer = printer;

	/*
	 * If the filters have't been loaded yet, do so now.
	 * We'll load the standard table, but the caller can override
	 * this by first calling "loadfilters()" with the appropriate
	 * filter table name.
	 */
	if (!filters && loadfilters((char *)0) == -1)
		return (fl_none);

	/*
	 * Allocate and initialize space to hold additional
	 * information about each item in "parms".
	 * THIS SPACE MUST BE FREED BEFORE EXITING THIS ROUTINE!
	 */
	{
		register int		n;

		register PARM *		pp;
		register PARM *		ppt;

		register char **	p;



		for (n = 0, p = parms; *p; n++, p++)
			;
		n /= 2;
		n += NFIXED; /* for fixed parms (in/out/printer types) */

		if (!(S.parms = (PARM *)Malloc((n + 1) * sizeof (PARM)))) {
			errno = ENOMEM;
			return (fl_none);
		}

		for (ppt = parmtable; ppt->keyword; ppt++)
			ppt->flags &= ~X_USED;

		/*
		 * Load the parameter list with the fixed ``type''
		 * parameters. Mark them as used (if appropriate)
		 * so we don't pick them up from the callers list.
		 */
		pp = S.parms;
		for (ppt = parmtable; ppt < parmtable + NFIXED; ppt++) {
			pp->keyword = ppt->keyword;
			pp->flags = ppt->flags;
			if (ppt->flags & X_FIXED)
				pp->pvalue = ppt->pvalue;
			else
				pp->pvalue = parms + 1;
			if (!(ppt->flags & X_MANY))
				ppt->flags |= X_USED;
			pp++;
		}

		/*
		 * Copy each parameter from the caller supplied list
		 * to another list, adding information gathered from
		 * the keyword table. Note that some keywords should
		 * be given only once; additional occurrances in the
		 * caller's list will be ignored.
		 */
		for (p = parms; *p; p += 2)
			for (ppt = parmtable; ppt->keyword; ppt++)
				if (STREQU(*p, ppt->keyword) &&
						!(ppt->flags & X_USED)) {

					pp->keyword = ppt->keyword;
					pp->flags = ppt->flags;
					if (ppt->flags & X_FIXED)
						pp->pvalue = ppt->pvalue;
					else
						pp->pvalue = p + 1;

					if (!(ppt->flags & X_MANY))
						ppt->flags |= X_USED;

					pp++;
					break;

				}

		pp->keyword = 0;

	}

	/*
	 * Preview the list of filters, to rule out those that
	 * can't possibly work.
	 */
	{
		register _FILTER *	pf;

		for (pf = filters; pf->name; pf++) {

			pf->mark = FL_CLEAR;

			if (printer && !searchlist(printer, pf->printers))
				pf->mark = FL_SKIP;

			else if (printer_type &&
					!searchlist_t(&(S.printer_type),
							pf->printer_types))
				pf->mark = FL_SKIP;

		}
	}

	/*
	 * Find a pipeline that will convert the input-type to the
	 * output-type and map the parameters as well.
	 */
	if (!instantiate(&pipeline, &S.input_type, &S.output_type,
			check_pipeline, S.parms)) {
		ret = fl_none;
		goto Return;
	}

	if (!pipes) {
		ret = fl_both;
		goto Return;

	} else {
		register _FILTER *	pf;
		register _FILTER *	pfastf; /* first in fast pipe */
		register _FILTER *	pslowf; /* last in slow pipe */

		/*
		 * Found a pipeline, so now build it.
		 */

		/*
		 * Split pipeline after last slow filter.
		 * "pipeline" will point to first filter in slow
		 * pipe, "pfastf" will point to first filter in
		 * fast pipe.
		 */
		for (pf = pfastf = pipeline, pslowf = 0; pf; pf = pf->next)
			if (pf->type == fl_slow) {
				pslowf = pf;
				pfastf = pf->next;
			}

		if (pslowf) {
			assert(pslowf != pfastf);
			pslowf->next = 0;
			pipes[0] = build_pipe(pipeline, S.parms, flagsp);
			ret = fl_slow;
		} else
			pipes[0] = 0;

		if (pfastf) {
			pipes[1] = build_pipe(pfastf, S.parms, flagsp);
			ret = fl_fast;
		} else
			pipes[1] = 0;

		if (pslowf && pfastf)
			ret = fl_both;

		/*
		 * Check for the oops case.
		 */
		if (pslowf && !pipes[0] || pfastf && !pipes[1])
			ret = fl_none;

	}

Return:	Free((char *)S.parms);

	return (ret);
}

/*
 * searchlist_t() - SEARCH (TYPE *) LIST FOR ITEM
 */

static int
#if	defined(__STDC__)
typematch(
	TYPE			*type1,
	TYPE			*type2
)
#else
typematch(type1, type2)
	TYPE			*type1, *type2;
#endif
{
	if (STREQU(type1->name, NAME_ANY) || STREQU(type2->name, NAME_ANY) ||
			STREQU(type1->name, type2->name) ||
			(STREQU(type1->name, NAME_TERMINFO) && type2->info) ||
			(STREQU(type2->name, NAME_TERMINFO) && type1->info))
		return (1);
	else
		return (0);
}

static int
#if	defined(__STDC__)
searchlist_t(
	TYPE			*itemp,
	TYPE			*list
)
#else
searchlist_t(itemp, list)
	TYPE			*itemp;
	register TYPE		*list;
#endif
{
	if (!list || !list->name)
		return (0);

	/*
	 * This is a linear search--we believe that the lists
	 * will be short.
	 */
	while (list->name) {
		if (typematch(itemp, list))
			return (1);
		list++;
	}
	return (0);
}

/*
 * instantiate() - CREATE FILTER-PIPELINE KNOWING INPUT/OUTPUT TYPES
 */

/*
 *	The "instantiate()" routine is the meat of the "insfilter()"
 *	algorithm. It is given an input-type and output-type and finds a
 *	filter-pipline that will convert the input-type into the
 *	output-type. Since the filter-pipeline must meet other criteria,
 *	a function "verify" is also given, along with the set of criteria;
 *	these are used by "instantiate()" to verify a filter-pipeline.
 *
 *	The filter-pipeline is built up and returned in "pipeline".
 *	Conceptually this is just a list of filters, with the pipeline to
 *	be constructed by simply concatenating the filter simple-commmands
 *	(after filling in option templates) in the order found in the
 *	list. What is used in the routine, though, is a pair of linked
 *	lists, one list forming the ``right-half'' of the pipeline, the
 *	other forming the ``left-half''. The pipeline is then the two
 *	lists taken together.
 *
 *	The "instantiate()" routine looks for a single filter that matches
 *	the input-type and output-type and satisfies the criteria. If one
 *	is found, it is added to the end of the ``left-half'' list (it
 *	could be added to the beginning of the ``right-half'' list with no
 *	problem). The two lists are linked together to form one linked
 *	list, which is passed, along with the set of criteria, to the
 *	"verify" routine to check the filter-pipeline. If it passes the
 *	check, the work is done.
 *
 *	If a single filter is not found, "instantiate()" examines all
 *	pairs of filters where one in the pair can accept the input-type
 *	and the other can produce the output-type. For each of these, it
 *	calls itself again to find a filter that can join the pair
 *	together--one that accepts as input the output-type of the first
 *	in the pair, and produces as output the input-type of the second
 *	in the pair.  This joining filter may be a single filter or may
 *	be a filter-pipeline. "instantiate()" checks for the trivial case
 *	where the input-type is the output-type; with trivial cases it
 *	links the two lists without adding a filter and checks it with
 *	"verify".
 */

/*
 * instantiate()
 */

/*
 * A PIPELIST is what is passed to each recursive call to "instantiate()".
 * It contains a pointer to the end of the ``left-list'', a pointer to the
 * head of the ``right-list'', and a pointer to the head of the left-list.
 * The latter is passed to "verify". The end of the right-list (and thus
 * the end of the entire list when left and right are joined) is the
 * filter with a null ``next'' pointer.
 */
typedef struct PIPELIST {
	_FILTER *		lhead;
	_FILTER *		ltail;
	_FILTER *		rhead;
}			PIPELIST;

#if	defined(__STDC__)
static int		_instantiate(PIPELIST *, TYPE *, TYPE *,
					int (*)(_FILTER *, void *), void *);
#else
static int		_instantiate();
#endif

static int		peg;

static int
#if	defined(__STDC__)
instantiate(
	_FILTER			**pline,
	TYPE			*input,
	TYPE			*output,
	int			(*verify)(_FILTER *, void *),
	void			*criteria
)
#else
instantiate(pline, input, output, verify, criteria)
	_FILTER			**pline;
	TYPE			*input,
				*output;
	int			(*verify)();
	char			*criteria;
#endif
{
	PIPELIST		p;
	int			ret;

	peg = 0;
	p.lhead = p.ltail = p.rhead = 0;
	ret = _instantiate(&p, input, output, verify, criteria);
	*pline = p.lhead;
	return (ret);
}

#define	ENTER()		int our_tag; our_tag = ++peg;

#define	LEAVE(Y)	if (!Y) { \
				register _FILTER *f; \
				for (f = filters; f->name; f++) \
					CLEAR(f); \
				return (0); \
			} else \
				return (1)

#define	MARK(F, M)	(((F)->mark |= M), (F)->level = our_tag)

#define	CLEAR(F)	if ((F)->level == our_tag) \
				(F)->level = 0, (F)->mark = FL_CLEAR

#define	CHECK(F, M)	(((F)->mark & M) && (F)->level == our_tag)

#define	USED(F)		((F)->mark)

static int
#if	defined(__STDC__)
_instantiate(
	PIPELIST		*pp,
	TYPE			*inputp,
	TYPE			*outputp,
	int			(*verify)(_FILTER *, void *),
	void			*criteria
)
#else
_instantiate(pp, inputp, outputp, verify, criteria)
	PIPELIST		*pp;
	TYPE			*inputp,
				*outputp;
	int			(*verify)();
	char			*criteria;
#endif
{
	register _FILTER	*prev_lhead;
	register _FILTER	*prev_ltail;


	/*
	 * Must be first ``statement'' after declarations.
	 */
	ENTER();

	/*
	 * We're done when we've added filters on the left and right
	 * that let us connect the left and right directly; i.e. when
	 * the output of the left is the same type as the input of the
	 * right. HOWEVER, there must be at least one filter involved,
	 * to allow the filter feature to be used for handling modes,
	 * pages, copies, etc. not just FILTERING data.
	 */
	if (typematch(inputp, outputp) && pp->lhead) {

		/*
		 * Getting here means that we must have a left and right
		 * pipeline. Why? For "pp->lhead" to be non-zero it
		 * must have been set below. The first place below
		 * doesn't set the right pipeline, but it also doesn't
		 * get us here (at least not directly). The only
		 * place we can get to here again is the second place
		 * "pp->phead" is set, and THAT sets the right pipeline.
		 */
		pp->ltail->next = pp->rhead;
		if ((*verify)(pp->lhead, criteria))
			LEAVE(1);
		else
			LEAVE(0);

	}

	/*
	 * Each time we search the list of filters, we examine
	 * them in the order given and stop searching when a filter
	 * that meets the needs is found. If the list is ordered with
	 * fast filters before slow filters, then fast filters will
	 * be chosen over otherwise-equal filters.
	 */

	/*
	 * See if there's a single filter that will work.
	 * Just in case we can't find one, mark those that
	 * will work as left- or right-filters, to save time
	 * later.
	 *
	 * Also, record exactly *which* input/output
	 * type would be needed if the filter was used.
	 * This record will be complete (both input and output
	 * recorded) IF the single filter works. Otherwise,
	 * only the input, for the left possible filters,
	 * and the output, for the right possible filters,
	 * will be recorded. Thus, we'll have to record the
	 * missing types later.
	 */
	{
		register _FILTER *		pf;


		for (pf = filters; pf->name; pf++) {

			if (USED(pf))
				continue;

			if (searchlist_t(inputp, pf->input_types)) {
				MARK(pf, FL_LEFT);
				pf->inputp = inputp;
			}
			if (searchlist_t(outputp, pf->output_types)) {
				MARK(pf, FL_RIGHT);
				pf->outputp = outputp;
			}

			if (CHECK(pf, FL_LEFT) && CHECK(pf, FL_RIGHT)) {
				prev_lhead = pp->lhead;
				prev_ltail = pp->ltail;

				if (!pp->lhead)
					pp->lhead = pf;
				else
					pp->ltail->next = pf;
				(pp->ltail = pf)->next = pp->rhead;

				if ((*verify)(pp->lhead, criteria))
					LEAVE(1);

				if ((pp->ltail = prev_ltail))
					pp->ltail->next = 0;
				pp->lhead = prev_lhead;

			}

		}
	}

	/*
	 * Try all DISJOINT pairs of left- and right-filters; recursively
	 * call this function to find a filter that will connect
	 * them (it might be a ``null'' filter).
	 */
	{
		register _FILTER *	pfl;
		register _FILTER *	pfr;

		register TYPE *		llist;
		register TYPE *		rlist;


		for (pfl = filters; pfl->name; pfl++) {

			if (!CHECK(pfl, FL_LEFT))
				continue;

			for (pfr = filters; pfr->name; pfr++) {

				if (pfr == pfl || !CHECK(pfr, FL_RIGHT))
					continue;

				prev_lhead = pp->lhead;
				prev_ltail = pp->ltail;

				if (!pp->lhead)
					pp->lhead = pfl;
				else
					pp->ltail->next = pfl;
				(pp->ltail = pfl)->next = 0;

				pfr->next = pp->rhead;
				pp->rhead = pfr;

				/*
				 * Try all the possible output types of
				 * the left filter with all the possible
				 * input types of the right filter. If
				 * we find a combo. that works, record
				 * the output and input types for the
				 * respective filters.
				 */
				for (llist = pfl->output_types; llist->name;
								llist++)
					for (rlist = pfr->input_types;
							rlist->name; rlist++)
						if (_instantiate(pp, llist,
								rlist, verify,
								criteria)) {
							pfl->outputp = llist;
							pfr->inputp = rlist;
							LEAVE(1);
						}
				pp->rhead = pfr->next;
				if ((pp->ltail = prev_ltail))
					pp->ltail->next = 0;
				pp->lhead = prev_lhead;

			}

		}
	}

	LEAVE(0);
}

/*
 * check_pipeline() - CHECK THAT PIPELINE HANDLES MODES, PAGE-LIST
 */

static int
#if	defined(__STDC__)
check_pipeline(
	_FILTER			*pipeline,
	PARM			*parms
)
#else
check_pipeline(pipeline, parms)
	_FILTER			*pipeline;
	PARM			*parms;
#endif
{
	register PARM		*pm;

	register _FILTER	*pf;

	register TEMPLATE	*pt;

	register int		fail;


	for (fail = 0, pm = parms; !fail && pm->keyword; pm++) {

		if (!(pm->flags & X_MUST))
			continue;

		for (pf = pipeline; pf; pf = pf->next) {

			if (!(pt = pf->templates))
				continue;

			for (; pt->keyword; pt++)
				if (STREQU(pt->keyword, pm->keyword) &&
						pt->result && MATCH(pt, pm))
					goto Okay;

		}
		fail = 1;
		continue;

Okay:;

	}

	return (fail? 0 : 1);
}

/*
 * build_filter() - CONSTRUCT PIPELINE FROM LINKED LIST OF FILTERS
 */

#if	defined(__STDC__)
static size_t		build_simple_cmd(char **, _FILTER *, PARM *,
							unsigned short *);
#else
static size_t		build_simple_cmd();
#endif

static char *
#if	defined(__STDC__)
build_pipe(
	_FILTER			*pipeline,
	PARM			*parms,
	unsigned short		*fp
)
#else
build_pipe(pipeline, parms, fp)
	_FILTER			*pipeline;
	PARM			*parms;
	unsigned short		*fp;
#endif
{
	register _FILTER	*pf;

	register size_t		nchars;
	register size_t		n;

	char			*p;	/* NOT register */
	char			*ret;


	/*
	 * This is a two-pass routine. In the first pass we add
	 * up how much space is needed for the pipeline, in the second
	 * pass we allocate the space and construct the pipeline.
	 */

	for (nchars = 0, pf = pipeline; pf; pf = pf->next)
		if ((n = build_simple_cmd((char **)0, pf, parms, fp)) > 0)
			nchars += n + 1;   /* +1 for '|' or ending null */

	if (!(ret = p = Malloc(nchars))) {
		errno = ENOMEM;
		return (0);
	}

	for (pf = pipeline; pf; pf = pf->next, *p++ = (pf? '|' : 0))
		(void) build_simple_cmd(&p, pf, parms, fp);

	return (ret);
}

/*
 * build_simple_cmd()
 */

static size_t
#if	defined(__STDC__)
build_simple_cmd(
	char			**pp,
	_FILTER			*pf,
	PARM			*parms,
	unsigned short		*flagsp
)
#else
build_simple_cmd(pp, pf, parms, flagsp)
	char			**pp;
	_FILTER			*pf;
	PARM			*parms;
	unsigned short		*flagsp;
#endif
{
	register size_t		ncount;

	register TEMPLATE	*pt;

	register PARM		*pm;


	if (pf->command) {
		ncount = strlen(pf->command);
		if (pp) {
			strcpy (*pp, pf->command);
			*pp += ncount;
		}
	} else
		ncount = 0;

	if (!pf->templates)
		return (ncount);

	for (pm = parms; pm->keyword; pm++) {

		if ((pm->flags & X_USED) || !*(pm->pvalue))
			continue;

		for (pt = pf->templates; pt->keyword; pt++) {

			if (!STREQU(pt->keyword, pm->keyword) || !pt->result)
				continue;

			/*
			 * INPUT and OUTPUT are those for *this* filter,
			 * not for the entire pipeline.
			 */
			if (STREQU(pt->keyword, PARM_INPUT))
				pm->pvalue = &(pf->inputp->name);
			else if (STREQU(pt->keyword, PARM_OUTPUT))
				pm->pvalue = &(pf->outputp->name);

			if (MATCH(pt, pm)) {
				if (pp)
					*(*pp)++ = ' ';
				ncount++;

				ncount += replace(pp, pt->result,
						*(pm->pvalue), pt->nbra);

				/*
				 * Difficulty here due to the two pass
				 * nature of this code. The first pass
				 * just counts the number of bytes; if
				 * we mark the once-only parms as being
				 * used, then we don't pick them up the
				 * second time through. We could get
				 * difficult and mark them temporarily,
				 * but that's hard. So on the first pass
				 * we don't mark the flags. The only
				 * problem is an estimate too high.
				 */
				if (pp && pm->flags & X_FIRST)
					pm->flags |= X_USED;

				*flagsp |= pm->flags;

			}
		}
	}

	return (ncount);
}
