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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

#include	<sys/types.h>
#include	<stdarg.h>
#include	<stdio.h>
#include	<dlfcn.h>
#include	<signal.h>
#include	<locale.h>
#include	<string.h>
#include	<libintl.h>
#include	<debug.h>
#include	"_rtld.h"
#include	"msg.h"

/*
 * Structure for maintaining sorting state.
 */
typedef struct {
	Rt_map		**s_lmpa;	/* link-map[] (returned to caller) */
	Rt_map		*s_lmp;		/* originating link-map */
	Rt_map		**s_stack;	/* strongly connected component stack */
	APlist 		*s_scc;		/* cyclic list */
	APlist		*s_queue;	/* depth queue for cyclic components */
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
	Lm_list			*lml = LIST(sort->s_lmp);
	Word			lmflags = lml->lm_flags;
	Word			init, unref;

	/*
	 * If this is the first cyclic dependency traverse the new objects that
	 * have been added to the link-map list and for each object establish
	 * a unique depth index.  We build this dynamically as we have no idea
	 * of the number of objects that will be inspected (logic matches that
	 * used by dlsym() to traverse lazy dependencies).
	 */
	if (sort->s_queue == NULL) {
		Aliste	idx1;
		Rt_map	*lmp, *lmp2;

		lmp = sort->s_lmp;
		ndx = 1;

		if (aplist_append(&sort->s_queue, lmp, sort->s_num) == NULL)
			return (0);

		IDX(lmp) = ndx++;

		for (APLIST_TRAVERSE(sort->s_queue, idx1, lmp2)) {
			Bnd_desc	*bdp;
			Aliste		idx2;

			for (APLIST_TRAVERSE(DEPENDS(lmp2), idx2, bdp)) {
				Rt_map	*lmp = bdp->b_depend;

				if (IDX(lmp))
					continue;

				/*
				 * If we're .init processing and this depend-
				 * encies .init has been called, skip it.
				 */
				if ((flag & RT_SORT_REV) &&
				    (FLAGS(lmp) & FLG_RT_INITCALL))
					continue;

				if (aplist_append(&sort->s_queue, lmp,
				    sort->s_num) == NULL)
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
	    ((unref = (lmflags & LML_FLG_TRC_UNREF)) == 0) &&
	    (DBG_ENABLED == 0))
		return (1);

	if (init) {
		if (tfmt == 0) {
			tfmt = MSG_INTL(MSG_LDD_INIT_FMT_01);
			ffmt = MSG_ORIG(MSG_LDD_INIT_FMT_FILE);
		}
		(void) printf(tfmt, cnt);
	}
	DBG_CALL(Dbg_util_scc_title(lml, (flag & RT_SORT_REV)));

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
			DBG_CALL(Dbg_util_scc_entry(lmp, ndx));
		}
		cnt++;

	} else if (DBG_ENABLED) {
		for (ndx = sort->s_lndx - 1; ndx >= fndx; ndx--) {
			lmp = sort->s_lmpa[ndx];
			DBG_CALL(Dbg_util_scc_entry(lmp, ndx));
		}
	}

	/*
	 * If we're looking for unused dependencies determine if any of these
	 * cyclic components are referenced from outside of the cycle.
	 */
	if (unref || DBG_ENABLED) {
		for (ndx = fndx; ndx < sort->s_lndx; ndx++) {
			Bnd_desc	*bdp;
			Aliste		idx;

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
			for (APLIST_TRAVERSE(CALLERS(lmp), idx, bdp)) {
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
visit(Lm_list *lml, Rt_map * lmp, Sort *sort, int flag)
{
	APlist		*alp = NULL;
	int		num = sort->s_lndx;
	Word		tracing = lml->lm_flags & LML_FLG_TRC_ENABLE;
	Rt_map		*tlmp;

	do {
		tlmp = sort->s_stack[--(sort->s_sndx)];
		SORTVAL(tlmp) = sort->s_num;
		DBG_CALL(Dbg_util_collect(tlmp, sort->s_lndx, flag));
		sort->s_lmpa[(sort->s_lndx)++] = tlmp;

		if (flag & RT_SORT_REV) {
			/*
			 * Indicate the object has had its .init collected.
			 * Note, that regardless of the object having a .init
			 * the object is added to the tsort list, as it's from
			 * this list that any post-init flags are established.
			 */
			FLAGS(tlmp) |= FLG_RT_INITCLCT;
			lml->lm_init--;
		} else {
			/*
			 * Indicate the object has had its .fini collected.
			 * Note, that regardless of the object having a .fini,
			 * the object is added to the tsort list, as it's from
			 * this list that any audit_objclose() activity is
			 * triggered.
			 */
			FLAGS(tlmp) |= FLG_RT_FINICLCT;
		}

		/*
		 * If tracing, save the strongly connected component.
		 */
		if (tracing && (aplist_append(&alp, tlmp,
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

		if (tracing && (aplist_append(&sort->s_scc, alp,
		    AL_CNT_SCC) == 0))
			return (0);
	} else if (alp)
		free(alp);

	return (1);
}

static int
dep_visit(Lm_list *, Rt_map *, uint_t, Rt_map *, Sort *, int);

static int
_dep_visit(Lm_list *lml, int min, Rt_map *clmp, Rt_map *dlmp, uint_t bflags,
    Sort *sort, int flag)
{
	int	_min;

	/*
	 * Only collect objects that belong to the callers link-map.  Catches
	 * cross dependencies (filtering) to ld.so.1.
	 */
	if (LIST(dlmp) != lml)
		return (min);

	/*
	 * Determine if this object hasn't been inspected.
	 */
	if ((_min = SORTVAL(dlmp)) == -1) {
		if (flag & RT_SORT_REV) {
			/*
			 * For .init processing, only collect objects that have
			 * been relocated and haven't already been collected.
			 */
			if ((FLAGS(dlmp) & (FLG_RT_RELOCED |
			    FLG_RT_INITCLCT)) != FLG_RT_RELOCED)
				return (min);

			/*
			 * If this object contains no .init, there's no need to
			 * establish a dependency.
			 */
			if ((INIT(dlmp) == 0) && (INITARRAY(dlmp) == 0))
				return (min);
		} else {
			/*
			 * For .fini processing only collect objects that have
			 * had their .init collected, and haven't already been
			 * .fini collected.
			 */
			if ((FLAGS(dlmp) & (FLG_RT_INITCLCT |
			    FLG_RT_FINICLCT)) != FLG_RT_INITCLCT)
				return (min);

			/*
			 * If we're deleting a subset of objects, only collect
			 * those marked for deletion.
			 */
			if ((flag & RT_SORT_DELETE) &&
			    ((FLAGS(dlmp) & FLG_RT_DELETE) == 0))
				return (min);

			/*
			 * If this object contains no .fini, there's no need to
			 * establish a dependency.
			 */
			if ((FINI(dlmp) == 0) && (FINIARRAY(dlmp) == 0))
				return (min);
		}

		/*
		 * Inspect this new dependency.
		 */
		if ((_min = dep_visit(lml, clmp, bflags, dlmp,
		    sort, flag)) == -1)
			return (-1);
	}

	/*
	 * Keep track of the smallest SORTVAL that has been encountered.  If
	 * this value is smaller than the present object, then the dependency
	 * edge has cycled back to objects that have been processed earlier
	 * along this dependency edge.
	 */
	if (_min < min) {
		DBG_CALL(Dbg_util_edge_out(clmp, sort->s_stack[_min]));
		return (_min);
	} else
		return (min);
}

/*
 * Visit the dependencies of each object.
 */
static int
dep_visit(Lm_list *lml, Rt_map *clmp, uint_t cbflags, Rt_map *lmp, Sort *sort,
    int flag)
{
	int 		min;
	Aliste		idx;
	Bnd_desc	*bdp;
	Dyninfo		*dip;

	min = SORTVAL(lmp) = sort->s_sndx;
	sort->s_stack[(sort->s_sndx)++] = lmp;

	if (FLAGS(lmp) & FLG_RT_INITFRST)
		sort->s_initfirst++;

	DBG_CALL(Dbg_util_edge_in(lml, clmp, cbflags, lmp, min, flag));

	/*
	 * Traverse both explicit and implicit dependencies.
	 */
	for (APLIST_TRAVERSE(DEPENDS(lmp), idx, bdp)) {
		if ((min = _dep_visit(lml, min, lmp, bdp->b_depend,
		    bdp->b_flags, sort, flag)) == -1)
			return (-1);
	}

	/*
	 * Traverse any filtee dependencies.
	 */
	if (((dip = DYNINFO(lmp)) != 0) && (FLAGS1(lmp) & MSK_RT_FILTER)) {
		uint_t	cnt, max = DYNINFOCNT(lmp);

		for (cnt = 0; cnt < max; cnt++, dip++) {
			Pnode	*pnp = (Pnode *)dip->di_info;

			if ((pnp == 0) ||
			    ((dip->di_flags & MSK_DI_FILTER) == 0))
				continue;

			for (; pnp; pnp = pnp->p_next) {
				Grp_hdl		*ghp = (Grp_hdl *)dip->di_info;
				Grp_desc	*gdp;

				if ((pnp->p_len == 0) ||
				    ((ghp = (Grp_hdl *)pnp->p_info) == 0))
					continue;

				for (ALIST_TRAVERSE(ghp->gh_depends, idx,
				    gdp)) {

					if (gdp->gd_depend == lmp)
						continue;
					if ((min = _dep_visit(lml, min, lmp,
					    gdp->gd_depend, BND_FILTER,
					    sort, flag)) == -1)
						return (-1);
				}
			}
		}
	}

	/*
	 * Having returned to where the minimum SORTVAL is equivalent to the
	 * object that has just been processed, collect any dependencies that
	 * are available on the sorting stack.
	 */
	if (min == SORTVAL(lmp)) {
		if (visit(lml, lmp, sort, flag) == 0)
			return (-1);
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

	if ((nlmp = NEXT_RT_MAP(lmp)) != 0)
		rb_visit(nlmp, sort);

	/*
	 * Only collect objects that have been relocated and haven't already
	 * been collected.
	 */
	if ((FLAGS(lmp) & (FLG_RT_RELOCED | FLG_RT_INITCLCT)) ==
	    FLG_RT_RELOCED) {
		sort->s_lmpa[(sort->s_lndx)++] = lmp;
		FLAGS(lmp) |= FLG_RT_INITCLCT;
		LIST(lmp)->lm_init--;
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
		lmp = NEXT_RT_MAP(lmp);
	}
}
#endif

/*
 * Find corresponding strongly connected component structure.
 */
static APlist *
trace_find_scc(Sort *sort, Rt_map *lmp)
{
	APlist		*alp;
	Aliste		idx1;

	for (APLIST_TRAVERSE(sort->s_scc, idx1, alp)) {
		Rt_map	*lmp2;
		Aliste	idx2;

		for (APLIST_TRAVERSE(alp, idx2, lmp2)) {
			if (lmp == lmp2)
				return (alp);
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
	APlist		*alp;
	Rt_map		*lmp1;

	(void) printf(MSG_ORIG(MSG_STR_NL));

	while ((lmp1 = sort->s_lmpa[ndx++]) != NULL) {
		static const char	*ffmt, *cfmt = 0, *sfmt = 0;
		Bnd_desc		*bdp;
		Aliste			idx1;

		if ((INIT(lmp1) == 0) || (FLAGS(lmp1) & FLG_RT_INITCALL))
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

		for (APLIST_TRAVERSE(CALLERS(lmp1), idx1, bdp)) {
			Rt_map	*lmp3, *lmp2 = bdp->b_caller;
			Aliste	idx2;

			for (APLIST_TRAVERSE(alp, idx2, lmp3)) {
				if (lmp2 != lmp3)
					continue;

				(void) printf(ffmt, NAME(lmp3));
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
 * Determine whether .init or .fini processing is required.
 */
static int
initorfini(Lm_list *lml, Rt_map *lmp, int flag, Sort *sort)
{
	if (flag & RT_SORT_REV) {
		/*
		 * For .init processing, only collect objects that have been
		 * relocated and haven't already been collected.
		 */
		if ((FLAGS(lmp) & (FLG_RT_RELOCED | FLG_RT_INITCLCT)) !=
		    FLG_RT_RELOCED)
			return (0);

		if (dep_visit(lml, 0, 0, lmp, sort, flag) == -1)
			return (1);

	} else if (!(flag & RT_SORT_DELETE) || (FLAGS(lmp) & FLG_RT_DELETE)) {
		/*
		 * Only collect objects that have had their .init collected,
		 * and haven't already been .fini collected.
		 */
		if (!((FLAGS(lmp) & (FLG_RT_INITCLCT | FLG_RT_FINICLCT)) ==
		    (FLG_RT_INITCLCT)))
			return (0);

		if (dep_visit(lml, 0, 0, lmp, sort, flag) == -1)
			return (1);
	}
	return (0);
}

/*
 * Sort the dependency
 */
Rt_map **
tsort(Rt_map *lmp, int num, int flag)
{
	Rt_map *	_lmp;
	Lm_list *	lml = LIST(lmp);
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
		 * If tracing .init sections (only meaningful for RT_SORT_REV)
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
	 * start searching.  However, if new objects have dependencies on
	 * existing objects, or existing objects have been promoted (RTLD_LAZY
	 * to RTLD_NOW), then start searching at the head of the link-map list.
	 * These previously loaded objects will have been tagged for inclusion
	 * in this tsort() pass.  They still remain on an existing tsort() list,
	 * which must have been prempted for control to have arrived here.
	 * However, they will be ignored when encountered on any previous
	 * tsort() list if their .init has already been called.
	 */
	if (lml->lm_flags & LML_FLG_OBJREEVAL)
		_lmp = lml->lm_head;
	else
		_lmp = lmp;

	DBG_CALL(Dbg_file_bindings(_lmp, flag));
	lml->lm_flags &=
	    ~(LML_FLG_OBJREEVAL | LML_FLG_OBJADDED | LML_FLG_OBJDELETED);

	/*
	 * If interposers exist, inspect these objects first.
	 *
	 * Interposers can provide implicit dependencies - for example, an
	 * application that has a dependency on libumem will caused any other
	 * dependencies of the application that use the malloc family, to
	 * have an implicit dependency on libumem.  However, under the default
	 * condition of lazy binding, these dependency relationships on libumem
	 * are unknown to the tsorting process (ie. a call to one of the malloc
	 * family has not occurred to establish the dependency).  This lack of
	 * dependency information makes the interposer look "standalone",
	 * whereas the interposers .init/.fini should be analyzed with respect
	 * to the dependency relationship libumem will eventually create.
	 *
	 * By inspecting interposing objects first, we are able to trigger
	 * their .init sections to be accounted for before any others.
	 * Selecting these .init sections first is important for the malloc
	 * libraries, as these libraries need to prepare for pthread_atfork().
	 * However, handling interposer libraries in this generic fashion
	 * should help provide for other dependency relationships that may
	 * exist.
	 */
	if ((lml->lm_flags & (LML_FLG_INTRPOSE | LML_FLG_INTRPOSETSORT)) ==
	    LML_FLG_INTRPOSE) {
		Rt_map	*ilmp = _lmp;

		/*
		 * Unless the executable is tagged as an interposer, skip to
		 * the next object.
		 */
		if ((FLAGS(ilmp) & MSK_RT_INTPOSE) == 0)
			ilmp = NEXT_RT_MAP(ilmp);

		for (; ilmp; ilmp = NEXT_RT_MAP(ilmp)) {
			if ((FLAGS(ilmp) & MSK_RT_INTPOSE) == 0)
				break;

			if (initorfini(lml, ilmp, (flag | RT_SORT_INTPOSE),
			    &sort) != 0)
				return ((Rt_map **)S_ERROR);
		}

		/*
		 * Once all interposers are processed, there is no need to
		 * look for interposers again.  An interposer can only
		 * be introduced before any relocation takes place, thus
		 * interposer .init's will be grabbed during the first tsort
		 * starting at the head of the link-map list.
		 *
		 * Interposers can't be unloaded.  Thus interposer .fini's can
		 * only be called during atexit() processing.  The interposer
		 * tsort flag is removed from each link-map list during
		 * atexit_fini() so that the interposers .fini sections are
		 * processed appropriately.
		 */
		lml->lm_flags |= LML_FLG_INTRPOSETSORT;
	}

	/*
	 * Inspect any standard objects.
	 */
	for (; _lmp; _lmp = NEXT_RT_MAP(_lmp)) {
		if (FLAGS(_lmp) & MSK_RT_INTPOSE)
			continue;

		if (initorfini(lml, _lmp, flag, &sort) != 0)
			return ((Rt_map **)S_ERROR);
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
	 * If tracing .init sections (only meaningful for RT_SORT_REV), print
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
		Aliste idx;
		Rt_map	*lmp2;

		/*
		 * Traverse the link-maps collected on the sort queue and
		 * delete the depth index.  These link-maps may be traversed
		 * again to sort other components either for inits, and almost
		 * certainly for .finis.
		 */
		for (APLIST_TRAVERSE(sort.s_queue, idx, lmp2))
			IDX(lmp2) = 0;

		free(sort.s_queue);
	}

	if (sort.s_scc) {
		Aliste	idx;
		APlist	*alp;

		for (APLIST_TRAVERSE(sort.s_scc, idx, alp))
			free(alp);
		free(sort.s_scc);
	}

	/*
	 * The caller is responsible for freeing the sorted link-map list once
	 * the associated .init/.fini's have been fired.
	 */
	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));
	return (sort.s_lmpa);
}
