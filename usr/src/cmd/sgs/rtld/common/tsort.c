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
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utilities to handle shared object dependency graph.
 *
 * The algorithms used in this file are taken from the following book:
 *	Algorithms in C
 *		Robert Sedgewick
 *		Addison-Wesley Publishing company
 *		ISBN 0-201-51425-7
 * 	From the following chapters:
 *		Chapter 29 Elementary Graph Algorithms
 *		Chapter 32 Directed Graph
 */
#include	"_synonyms.h"

#include	<sys/types.h>
#include	<stdarg.h>
#include	<stdio.h>
#include	<dlfcn.h>
#include	<signal.h>
#include	<locale.h>
#include	<string.h>
#include	<libintl.h>
#include	"_rtld.h"
#include	"msg.h"
#include	"debug.h"

/*
 * Structure for maintaining sorting state.
 */
typedef struct {
	Rt_map		**s_lmpa;	/* link-map[] (returned to caller) */
	Rt_map		*s_lmp;		/* originating link-map */
	Rt_map		**s_stack;	/* strongly connected component stack */
	Alist 		*s_scc;		/* cyclic list */
	Alist		*s_queue;	/* depth queue for cyclic components */
	int		s_sndx;		/* present stack index */
	int 		s_lndx;		/* present link-map index */
	int		s_num;		/* number of objects to sort */
	int		s_initfirst;	/* no. of INITFIRST entries */
} Sort;

#define	AL_CNT_SCC	10

/*
 * qsort(3c) comparison function.
 */
static int
compare(const void * lmpp1, const void * lmpp2)
{
	Rt_map	*lmp1 = *((Rt_map **)lmpp1);
	Rt_map	*lmp2 = *((Rt_map **)lmpp2);

	if (IDX(lmp1) > IDX(lmp2))
		return (-1);
	if (IDX(lmp1) < IDX(lmp2))
		return (1);
	return (0);
}

/*
 * This routine is called when a cyclic dependency is detected between strongly
 * connected components.  The nodes within the cycle are reverse breadth-first
 * sorted.
 */
static int
sort_scc(Sort * sort, int fndx, int flag)
{
	static const char	*tfmt = 0, *ffmt;
	static int		cnt = 1;
	int			ndx;
	Rt_map			*lmp;
	Word			lmflags = LIST(sort->s_lmp)->lm_flags;
	Word			init, unref;

	/*
	 * If this is the first cyclic dependency traverse the new objects that
	 * have been added to the link-map list and for each object establish
	 * a unique depth index.  We build this dynamically as we have no idea
	 * of the number of objects that will be inspected (logic matches that
	 * used by dlsym() to traverse lazy dependencies).
	 */
	if (sort->s_queue == 0) {
		Aliste	off;
		Rt_map	*lmp, **lmpp;

		lmp = sort->s_lmp;
		ndx = 1;

		if (alist_append(&(sort->s_queue), &lmp, sizeof (Rt_map *),
		    sort->s_num) == 0)
			return (0);

		IDX(lmp) = ndx++;

		for (ALIST_TRAVERSE(sort->s_queue, off, lmpp)) {
			Bnd_desc	**bdpp;
			Aliste		off;

			for (ALIST_TRAVERSE(DEPENDS(*lmpp), off, bdpp)) {
				Rt_map	*lmp = (*bdpp)->b_depend;

				if (IDX(lmp))
					continue;

				/*
				 * If we're .init processing and this depend-
				 * encies .init has been called, skip it.
				 */
				if ((flag & RT_SORT_REV) &&
				    (FLAGS(lmp) & FLG_RT_INITCALL))
					continue;

				if (alist_append(&(sort->s_queue), &lmp,
				    sizeof (Rt_map *), sort->s_num) == 0)
					return (0);

				IDX(lmp) = ndx++;
			}
		}
	}

	/*
	 * Sort the cyclics.
	 */
	qsort(&(sort->s_lmpa[fndx]), sort->s_lndx - fndx, sizeof (Rt_map *),
	    compare);

	/*
	 * Under ldd -i, or debugging, print this cycle.  Under ldd -i/-U assign
	 * each object a group identifier so that cyclic dependent callers can
	 * be better traced (see trace_sort()), or analyzed for non-use.
	 */
	if (((init = (lmflags & LML_FLG_TRC_INIT)) == 0) &&
	    ((unref = (lmflags & LML_FLG_TRC_UNREF)) == 0) && (dbg_mask == 0))
		return (1);

	if (init) {
		if (tfmt == 0) {
			tfmt = MSG_INTL(MSG_LDD_INIT_FMT_01);
			ffmt = MSG_ORIG(MSG_LDD_INIT_FMT_FILE);
		}
		(void) printf(tfmt, cnt);
	}
	DBG_CALL(Dbg_scc_title(flag & RT_SORT_REV));

	/*
	 * Identify this cyclic group, and under ldd -i print the cycle in the
	 * order its components will be run.
	 */
	if (flag & RT_SORT_REV) {
		for (ndx = fndx; ndx < sort->s_lndx; ndx++) {
			lmp = sort->s_lmpa[ndx];
			CYCGROUP(lmp) = cnt;

			if (init)
				(void) printf(ffmt, NAME(lmp));
			DBG_CALL(Dbg_scc_entry(IDX(lmp), NAME(lmp)));
		}
		cnt++;

	} else if (dbg_mask) {
		for (ndx = sort->s_lndx - 1; ndx >= fndx; ndx--) {
			lmp = sort->s_lmpa[ndx];
			DBG_CALL(Dbg_scc_entry(IDX(lmp), NAME(lmp)));
		}
	}

	/*
	 * If we're looking for unused dependencies determine if any of these
	 * cyclic components are referenced from outside of the cycle.
	 */
	if (unref || dbg_mask) {
		Bnd_desc **	bdpp;

		for (ndx = fndx; ndx < sort->s_lndx; ndx++) {
			Aliste	off;

			lmp = sort->s_lmpa[ndx];

			/*
			 * If this object has a handle then it can be in use by
			 * anyone.
			 */
			if (HANDLES(lmp))
				return (1);

			/*
			 * Traverse this objects callers looking for outside
			 * references.
			 */
			for (ALIST_TRAVERSE(CALLERS(lmp), off, bdpp)) {
				Bnd_desc	*bdp = *bdpp;
				Rt_map		*clmp = bdp->b_caller;

				if ((bdp->b_flags & BND_REFER) == 0)
					continue;

				if (CYCGROUP(lmp) != CYCGROUP(clmp))
					return (1);
			}
		}

		/*
		 * If we're here then none of the cyclic dependents have been
		 * referenced from outside of the cycle, mark them as unused.
		 */
		for (ndx = fndx; ndx < sort->s_lndx; ndx++) {
			lmp = sort->s_lmpa[ndx];
			FLAGS1(lmp) &= ~FL1_RT_USED;
		}
	}
	return (1);
}

/*
 * Take elements off of the stack and move them to the link-map array. Typically
 * this routine just pops one strongly connected component (individual link-map)
 * at a time.  When a cyclic dependency has been detected the stack will contain
 * more than just the present object to process, and will trigger the later call
 * to sort_scc() to sort these elements.
 */
static int
visit(Lm_list *lml, Rt_map * lmp, Sort * sort, int flag)
{
	Alist		*alpp = 0;
	int		num = sort->s_lndx;
	Word		tracing = lml->lm_flags & LML_FLG_TRC_ENABLE;
	Rt_map		*tlmp;

	do {
		tlmp = sort->s_stack[--(sort->s_sndx)];
		sort->s_lmpa[(sort->s_lndx)++] = tlmp;

		if (flag & RT_SORT_REV) {
			FLAGS(tlmp) |= FLG_RT_INITCLCT;
			lml->lm_init--;
		} else
			FLAGS(tlmp) |= FLG_RT_FINICLCT;

		SORTVAL(sort->s_stack[sort->s_sndx]) = sort->s_num;

		/*
		 * If tracing, save the strongly connected component.
		 */
		if (tracing && (alist_append(&alpp, &tlmp, sizeof (Rt_map *),
		    AL_CNT_SCC) == 0))
			return (0);
	} while (tlmp != lmp);

	/*
	 * Determine if there are cyclic dependencies to process.  If so, sort
	 * the components, and retain them for tracing output.
	 */
	if (sort->s_lndx > (num + 1)) {
		if (sort_scc(sort, num, flag) == 0)
			return (0);

		if (tracing && (alist_append(&(sort->s_scc), &alpp,
		    sizeof (Alist *), AL_CNT_SCC) == 0))
			return (0);
	} else if (alpp)
		free(alpp);

	return (1);
}

/*
 * Visit the dependencies of each object.
 */
static uint_t
dep_visit(Rt_map *lmp, Lm_list *lml, Sort *sort, uint_t *id, int flag)
{
	uint_t 		min;
	Aliste		off;
	Bnd_desc **	bdpp;

	min = SORTVAL(lmp) = ++(*id);

	sort->s_stack[(sort->s_sndx)++] = lmp;

	if (FLAGS(lmp) & FLG_RT_INITFRST)
		sort->s_initfirst++;

	/*
	 * Traverse both explicit and implicit dependencies.
	 */
	for (ALIST_TRAVERSE(DEPENDS(lmp), off, bdpp)) {
		Rt_map *	dlmp = (*bdpp)->b_depend;
		uint_t		_min;

		/*
		 * Only collect objects that belong to the callers link-map.
		 */
		if (LIST(dlmp) != lml)
			continue;

		if (flag & RT_SORT_REV) {
			/*
			 * For .init processing, only collect objects that have
			 * been relocated and haven't already been collected.
			 */
			if ((FLAGS(dlmp) & (FLG_RT_RELOCED |
			    FLG_RT_INITCLCT)) != FLG_RT_RELOCED)
				continue;
		} else {
			/*
			 * For .fini processing only collect objects that have
			 * had their .init collected, and haven't already been
			 * .fini collected.
			 */
			if ((FLAGS(dlmp) & (FLG_RT_INITCLCT |
			    FLG_RT_FINICLCT)) != FLG_RT_INITCLCT)
				continue;

			/*
			 * If we're deleting a subset of objects only collect
			 * those marked for deletion.
			 */
			if ((flag & RT_SORT_DELETE) &&
			    ((FLAGS(dlmp) & FLG_RT_DELETE) == 0))
				continue;
		}

		if ((_min = SORTVAL(dlmp)) == 0) {
			if ((_min = dep_visit(dlmp, lml, sort, id, flag)) == 0)
				return (0);
		}
		if (_min < min)
			min = _min;
	}

	if (min == SORTVAL(lmp)) {
		if (visit(lml, lmp, sort, flag) == 0)
			return (0);
	}
	return (min);
}


#ifndef	LD_BREADTH_DISABLED
/*
 * Reverse LD_BREATH search (used to fire .init's the old fashioned way).
 */
static void
rb_visit(Rt_map * lmp, Sort * sort)
{
	Rt_map *	nlmp;

	if ((nlmp = (Rt_map *)NEXT(lmp)) != 0)
		rb_visit(nlmp, sort);

	/*
	 * Only collect objects that have been relocated and haven't already
	 * been collected.
	 */
	if ((FLAGS(lmp) & (FLG_RT_RELOCED | FLG_RT_INITCLCT)) ==
	    FLG_RT_RELOCED) {
		sort->s_lmpa[(sort->s_lndx)++] = lmp;
		FLAGS(lmp) |= FLG_RT_INITCLCT;
	}
}

/*
 * Forward LD_BREATH search (used to fire .fini's the old fashioned way).
 */
static void
fb_visit(Rt_map * lmp, Sort * sort, int flag)
{
	while (lmp) {
		/*
		 * If we're called from dlclose() then we only collect those
		 * objects marked for deletion.
		 */
		if (!(flag & RT_SORT_DELETE) || (FLAGS(lmp) & FLG_RT_DELETE)) {
			/*
			 * Only collect objects that have had their .init
			 * collected, and haven't already been .fini collected.
			 */
			if ((FLAGS(lmp) &
			    (FLG_RT_INITCLCT | FLG_RT_FINICLCT)) ==
			    (FLG_RT_INITCLCT)) {
				sort->s_lmpa[(sort->s_lndx)++] = lmp;
				FLAGS(lmp) |= FLG_RT_FINICLCT;
			}
		}
		lmp = (Rt_map *)NEXT(lmp);
	}
}
#endif

/*
 * Find corresponding strongly connected component structure.
 */
static Alist *
trace_find_scc(Sort * sort, Rt_map * lmp)
{
	Alist		**alpp;
	Aliste		off1;

	for (ALIST_TRAVERSE(sort->s_scc, off1, alpp)) {
		Rt_map	**lmpp;
		Aliste	off2;

		for (ALIST_TRAVERSE(*alpp, off2, lmpp)) {
			if (lmp == *lmpp)
				return (*alpp);
		}
	}
	return (NULL);
}

/*
 * Print out the .init dependency information (ldd).
 */
static void
trace_sort(Sort * sort)
{
	int 		ndx = 0;
	Alist		*alp;
	Rt_map		*lmp1;

	(void) printf(MSG_ORIG(MSG_STR_NL));

	while ((lmp1 = sort->s_lmpa[ndx++]) != NULL) {
		static const char	*ffmt, *cfmt = 0, *sfmt = 0;
		Bnd_desc **		bdpp;
		Aliste			off1;

		if (INIT(lmp1) == 0)
			continue;

		if (sfmt == 0)
			sfmt = MSG_INTL(MSG_LDD_INIT_FMT_02);

#ifndef	LD_BREADTH_DISABLED
		if (rtld_flags & RT_FL_BREADTH) {
			(void) printf(sfmt, NAME(lmp1));
			continue;
		}
#endif
		/*
		 * If the only component on the strongly connected list is
		 * this link-map, then there are no dependencies.
		 */
		if ((alp = trace_find_scc(sort, lmp1)) == NULL) {
			(void) printf(sfmt, NAME(lmp1));
			continue;
		}

		/*
		 * Establish message formats for cyclic dependencies.
		 */
		if (cfmt == 0) {
			cfmt = MSG_INTL(MSG_LDD_INIT_FMT_03);
			ffmt = MSG_ORIG(MSG_LDD_INIT_FMT_FILE);
		}

		(void) printf(cfmt, NAME(lmp1), CYCGROUP(lmp1));

		for (ALIST_TRAVERSE(CALLERS(lmp1), off1, bdpp)) {
			Rt_map	**lmpp3, *lmp2 = (*bdpp)->b_caller;
			Aliste	off2;

			for (ALIST_TRAVERSE(alp, off2, lmpp3)) {
				if (lmp2 != *lmpp3)
					continue;

				(void) printf(ffmt, NAME(*lmpp3));
			}
		}
	}
}

/*
 * A reverse ordered list (for .init's) contains INITFIRST elements.  Move each
 * of these elements to the front of the list.
 */
static void
r_initfirst(Sort * sort, int end)
{
	Rt_map *	tlmp;
	int		bgn, ifst, lifst = 0;

	for (bgn = 0; bgn < sort->s_initfirst; bgn++) {
		for (ifst = lifst; ifst <= end; ifst++) {
			tlmp = sort->s_lmpa[ifst];

			if (!(FLAGS(tlmp) & FLG_RT_INITFRST))
				continue;

			/*
			 * If the INITFIRST element is already at the front of
			 * the list leave it there.
			 */
			if (ifst == bgn) {
				lifst = ifst + 1;
				break;
			}

			/*
			 * Move the elements from the front of the list up to
			 * the INITFIRST element, back one position.
			 */
			(void) memmove(&sort->s_lmpa[bgn + 1],
			    &sort->s_lmpa[bgn],
			    ((ifst - bgn) * sizeof (Rt_map *)));

			/*
			 * Insert INITFIRST element at the front of the list.
			 */
			sort->s_lmpa[bgn] = tlmp;
			lifst = ifst + 1;
			break;
		}
	}
}

/*
 * A forward ordered list (for .fini's) contains INITFIRST elements.  Move each
 * of these elements to the front of the list.
 */
static void
f_initfirst(Sort * sort, int end)
{
	Rt_map *	tlmp;
	int		bgn, ifst, lifst = 0;

	for (bgn = 0; bgn < sort->s_initfirst; bgn++) {
		for (ifst = lifst; ifst <= end; ifst++) {
			tlmp = sort->s_lmpa[ifst];

			if (!(FLAGS(tlmp) & FLG_RT_INITFRST))
				continue;

			/*
			 * If the INITFIRST element is already at the end of
			 * the list leave it there.
			 */
			if (ifst == end)
				break;

			/*
			 * Move the elements from after the INITFIRST element
			 * up to the back of the list, up one position.
			 */
			(void) memmove(&sort->s_lmpa[ifst],
			    &sort->s_lmpa[ifst + 1],
			    ((end - ifst) * sizeof (Rt_map *)));

			/*
			 * Insert INITFIRST element at the back of the list.
			 */
			sort->s_lmpa[end--] = tlmp;
			lifst = ifst;
			break;
		}
	}
}

/*
 * Sort the dependency
 */
Rt_map **
tsort(Rt_map * lmp, int num, int flag)
{
	Rt_map *	_lmp;
	Lm_list *	lml = LIST(lmp);
	uint_t 		id = 0;
	Word		init = lml->lm_flags & LML_FLG_TRC_INIT;
	Sort		sort = { 0 };

	if (num == 0)
		return (0);

	/*
	 * Prior to tsorting any .init sections, insure that the `environ'
	 * symbol is initialized for this link-map list.
	 */
	if ((flag & RT_SORT_REV) && ((lml->lm_flags &
	    (LML_FLG_TRC_ENABLE | LML_FLG_ENVIRON)) == 0))
		set_environ(lml);

	/*
	 * Allocate memory for link-map list array.  Calloc the array to insure
	 * all elements are zero, we might find that no objects need processing.
	 */
	sort.s_lmp = lmp;
	sort.s_num = num + 1;
	if ((sort.s_lmpa = calloc(sort.s_num, sizeof (Rt_map *))) == NULL)
		return ((Rt_map **)S_ERROR);

#ifndef	LD_BREADTH_DISABLED
	/*
	 * A breadth first search is easy, simply add each object to the
	 * link-map array.
	 */
	if (rtld_flags & RT_FL_BREADTH) {
		if (flag & RT_SORT_REV)
			rb_visit(lmp, &sort);
		else
			fb_visit(lmp, &sort, flag);

		/*
		 * If tracing init sections (only meaningful for RT_SORT_REV)
		 * print out the sorted dependencies.
		 */
		if (init)
			trace_sort(&sort);

		return (sort.s_lmpa);
	}
#endif
	/*
	 * We need to topologically sort the dependencies.
	 */
	if ((sort.s_stack = malloc(sort.s_num * sizeof (Rt_map *))) == NULL)
		return ((Rt_map **)S_ERROR);

	/*
	 * Determine where to start searching for tsort() candidates.  Any call
	 * to tsort() for .init processing is passed the link-map from which to
	 * start searching.  However, previously loaded, uninitialized objects
	 * may be dependencies of newly loaded objects, and in this case start
	 * at the head of the link-map list, not the new link-map itself.
	 * These previously loaded objects will have been tagged for inclusion
	 * in this tsort() pass.  They still remain on an existing tsort() list,
	 * which must have been prempted for control to have arrived here.
	 * However, they will be ignored when encountered on any previous
	 * tsort() list if their init has already been called.
	 */
	if (LIST(lmp)->lm_flags & LML_FLG_BNDUNINIT) {
		LIST(lmp)->lm_flags &= ~LML_FLG_BNDUNINIT;
		_lmp = LIST(lmp)->lm_head;
	} else
		_lmp = lmp;

	for (; _lmp; _lmp = (Rt_map *)NEXT(_lmp)) {
		if (flag & RT_SORT_REV) {
			/*
			 * For .init processing, only collect objects that have
			 * been relocated and haven't already been collected.
			 */
			if ((FLAGS(_lmp) & (FLG_RT_RELOCED |
			    FLG_RT_INITCLCT)) != FLG_RT_RELOCED)
				continue;

			if (dep_visit(_lmp, lml, &sort, &id, flag) == 0)
				return ((Rt_map **)S_ERROR);

		} else if (!(flag & RT_SORT_DELETE) ||
		    (FLAGS(_lmp) & FLG_RT_DELETE)) {
			/*
			 * Only collect objects that have had their .init
			 * collected, and haven't already been .fini collected.
			 */
			if (!((FLAGS(_lmp) &
			    (FLG_RT_INITCLCT | FLG_RT_FINICLCT)) ==
			    (FLG_RT_INITCLCT)))
				continue;

			if (dep_visit(_lmp, lml, &sort, &id, flag) == 0)
				return ((Rt_map **)S_ERROR);
		}
	}

	/*
	 * The dependencies have been collected such that they are appropriate
	 * for an .init order, for .fini order reverse them.
	 */
	if (flag & RT_SORT_FWD) {
		int	bgn = 0, end = sort.s_lndx - 1;

		while (bgn < end) {
			Rt_map *	tlmp = sort.s_lmpa[end];

			sort.s_lmpa[end] = sort.s_lmpa[bgn];
			sort.s_lmpa[bgn] = tlmp;

			bgn++, end--;
		}
	}

	/*
	 * If INITFIRST objects have been collected then move them to the front
	 * or end of the list as appropriate.
	 */
	if (sort.s_initfirst) {
		if (flag & RT_SORT_REV)
			r_initfirst(&sort, sort.s_lndx - 1);
		else
			f_initfirst(&sort, sort.s_lndx - 1);
	}

	/*
	 * If tracing init sections (only meaningful for RT_SORT_REV), print
	 * out the sorted dependencies.
	 */
	if (init)
		trace_sort(&sort);

	/*
	 * Clean any temporary structures prior to return.
	 */
	if (sort.s_stack)
		free(sort.s_stack);

	if (sort.s_queue) {
		Aliste	off;
		Rt_map	**lmpp;

		/*
		 * Traverse the link-maps collected on the sort queue and
		 * delete the depth index.  These link-maps may be traversed
		 * again to sort other components either for .inits, and almost
		 * certainly for .finis.
		 */
		for (ALIST_TRAVERSE(sort.s_queue, off, lmpp))
			IDX(*lmpp) = 0;

		free(sort.s_queue);
	}

	if (sort.s_scc) {
		Aliste	off;
		Alist	**alpp;

		for (ALIST_TRAVERSE(sort.s_scc, off, alpp))
			free(*alpp);
		free(sort.s_scc);
	}

	/*
	 * The caller is responsible for freeing the sorted link-map list once
	 * the associated .init/.fini's have been fired.
	 */
	return (sort.s_lmpa);
}
