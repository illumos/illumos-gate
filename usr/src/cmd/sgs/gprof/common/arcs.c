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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	"gprof.h"

/*
 *	add (or just increment) an arc
 */
void
addarc(nltype *parentp, nltype *childp, actype count)
{
	arctype		*arcp;

#ifdef DEBUG
	if (debug & TALLYDEBUG) {
		(void) printf("[addarc] %lld arcs from %s to %s\n",
		    count, parentp->name, childp->name);
	}
#endif /* DEBUG */
	arcp = arclookup(parentp, childp);
	if (arcp != 0) {
		/*
		 *	a hit:  just increment the count.
		 */
#ifdef DEBUG
		if (!Dflag) {
			if (debug & TALLYDEBUG) {
				(void) printf("[tally] hit %lld += %lld\n",
				    arcp->arc_count, count);
			}
		} else {
			if (debug & TALLYDEBUG) {
				(void) printf("[tally] hit %lld -= %lld\n",
				    arcp->arc_count, count);
			}
		}

#endif /* DEBUG */
		if (!Dflag)
			arcp->arc_count += count;
		else {
			arcp->arc_count -= count;
			if (arcp->arc_count < 0)
				arcp->arc_count = 0;
		}
		return;
	}
	arcp = (arctype *)calloc(1, sizeof (*arcp));
	arcp->arc_parentp = parentp;
	arcp->arc_childp = childp;
	arcp->arc_count = count;
	/*
	 *	prepend this child to the children of this parent
	 */
	arcp->arc_childlist = parentp->children;
	parentp->children = arcp;
	/*
	 *	prepend this parent to the parents of this child
	 */
	arcp->arc_parentlist = childp->parents;
	childp->parents = arcp;
}

/*
 *	the code below topologically sorts the graph (collapsing cycles),
 *	and propagates time bottom up and flags top down.
 */

/*
 *	the topologically sorted name list pointers
 */
nltype	**topsortnlp;

static int
topcmp(const void *arg1, const void *arg2)
{
	nltype **npp1 = (nltype **)arg1;
	nltype **npp2 = (nltype **)arg2;

	return ((*npp1)->toporder - (*npp2)->toporder);
}

static void
timepropagate(nltype *parentp)
{
	arctype	*arcp;
	nltype	*childp;
	double	share;
	double	propshare;

	if (parentp->propfraction == 0.0) {
		return;
	}
	/*
	 *	gather time from children of this parent.
	 */
	for (arcp = parentp->children; arcp; arcp = arcp->arc_childlist) {
		childp = arcp->arc_childp;
		if (arcp->arc_count == 0) {
			continue;
		}
		if (childp == parentp) {
			continue;
		}
		if (childp->propfraction == 0.0) {
			continue;
		}
		if (childp->cyclehead != childp) {
			if (parentp->cycleno == childp->cycleno) {
				continue;
			}
			if (parentp->toporder <= childp->toporder) {
				(void) fprintf(stderr,
				    "[propagate] toporder botches\n");
			}
			childp = childp->cyclehead;
		} else {
			if (parentp->toporder <= childp->toporder) {
				(void) fprintf(stderr,
				    "[propagate] toporder botches\n");
				continue;
			}
		}
		if (childp->ncall == 0) {
			continue;
		}
		/*
		 *	distribute time for this arc
		 */
		arcp->arc_time = childp->time
		    * (((double)arcp->arc_count) /
		    ((double)childp->ncall));
		arcp->arc_childtime = childp->childtime
		    * (((double)arcp->arc_count) /
		    ((double)childp->ncall));
		share = arcp->arc_time + arcp->arc_childtime;
		parentp->childtime += share;
		/*
		 *	(1 - propfraction) gets lost along the way
		 */
		propshare = parentp->propfraction * share;
		/*
		 *	fix things for printing
		 */
		parentp->propchild += propshare;
		arcp->arc_time *= parentp->propfraction;
		arcp->arc_childtime *= parentp->propfraction;
		/*
		 *	add this share to the parent's cycle header, if any.
		 */
		if (parentp->cyclehead != parentp) {
			parentp->cyclehead->childtime += share;
			parentp->cyclehead->propchild += propshare;
		}
#ifdef DEBUG
		if (debug & PROPDEBUG) {
			(void) printf("[dotime] child \t");
			printname(childp);
			(void) printf(" with %f %f %lld/%lld\n",
			    childp->time, childp->childtime,
			    arcp->arc_count, childp->ncall);
			(void) printf("[dotime] parent\t");
			printname(parentp);
			(void) printf("\n[dotime] share %f\n", share);
		}
#endif /* DEBUG */
	}
}


static void
cycletime(void)
{
	int		cycle;
	nltype		*cyclenlp;
	nltype		*childp;

	for (cycle = 1; cycle <= ncycle; cycle += 1) {
		cyclenlp = &cyclenl[cycle];
		for (childp = cyclenlp->cnext; childp; childp = childp->cnext) {
			if (childp->propfraction == 0.0) {
				/*
				 * all members have the same propfraction
				 * except those that were excluded with -E
				 */
				continue;
			}
			cyclenlp->time += childp->time;
		}
		cyclenlp->propself = cyclenlp->propfraction * cyclenlp->time;
	}
}


static void
dotime(void)
{
	int	index;

	cycletime();
	for (index = 0; index < total_names; index += 1) {
		timepropagate(topsortnlp[index]);
	}
}


static void
cyclelink(void)
{
	nltype	*nlp;
	nltype	*cyclenlp;
	int		cycle;
	nltype		*memberp;
	arctype		*arcp;
	mod_info_t	*mi;

	/*
	 *	Count the number of cycles, and initialize the cycle lists
	 */
	ncycle = 0;
	for (mi = &modules; mi; mi = mi->next) {
		for (nlp = mi->nl; nlp < mi->npe; nlp++) {
			/*
			 *	this is how you find unattached cycles
			 */
			if (nlp->cyclehead == nlp && nlp->cnext != 0) {
				ncycle += 1;
			}
		}
	}

	/*
	 *	cyclenl is indexed by cycle number:
	 *	i.e. it is origin 1, not origin 0.
	 */
	cyclenl = (nltype *) calloc(ncycle + 1, sizeof (nltype));
	if (cyclenl == 0) {
		(void) fprintf(stderr,
		    "%s: No room for %d bytes of cycle headers\n",
		    whoami, (ncycle + 1) * sizeof (nltype));
		done();
	}

	/*
	 *	now link cycles to true cycleheads,
	 *	number them, accumulate the data for the cycle
	 */
	cycle = 0;
	for (mi = &modules; mi; mi = mi->next) {
		for (nlp = mi->nl; nlp < mi->npe; nlp++) {
			if (!(nlp->cyclehead == nlp && nlp->cnext != 0)) {
				continue;
			}
			cycle += 1;
			cyclenlp = &cyclenl[cycle];
			cyclenlp->name = 0;		/* the name */
			cyclenlp->value = 0;		/* pc entry point */
			cyclenlp->time = 0.0;		/* ticks in routine */
			cyclenlp->childtime = 0.0;	/* cumulative ticks */
							/*	in children */
			cyclenlp->ncall = 0;		/* how many times */
							/*	   called */
			cyclenlp->selfcalls = 0;	/* how many calls */
							/*	  to self */
			cyclenlp->propfraction = 0.0;	/* what % of time */
							/*	propagates */
			cyclenlp->propself = 0.0;	/* how much self time */
							/*	   propagates */
			cyclenlp->propchild = 0.0;	/* how much of child */
							/*   time propagates */
			cyclenlp->printflag = TRUE;	/* should this be */
							/*	 printed? */
			cyclenlp->index = 0;		/* index in the */
							/*   graph list */
			cyclenlp->toporder = DFN_NAN;	/* graph call chain */
							/*   top-sort order */
			cyclenlp->cycleno = cycle;	/* internal number */
							/*	of cycle on */
			cyclenlp->cyclehead = cyclenlp;	/* head of cycle ptr */
			cyclenlp->cnext = nlp;		/* ptr to next member */
							/*	of cycle */
			cyclenlp->parents = 0;		/* caller arcs list */
			cyclenlp->children = 0;		/* callee arcs list */
#ifdef DEBUG
			if (debug & CYCLEDEBUG) {
				(void) printf("[cyclelink] ");
				printname(nlp);
				(void) printf(" is the head of cycle %d\n",
				    cycle);
			}
#endif /* DEBUG */
			/*
			 *	link members to cycle header
			 */
			for (memberp = nlp; memberp; memberp = memberp->cnext) {
				memberp->cycleno = cycle;
				memberp->cyclehead = cyclenlp;
			}
			/*
			 *	count calls from outside the cycle
			 *	and those among cycle members
			 */
			for (memberp = nlp; memberp; memberp = memberp->cnext) {
				for (arcp = memberp->parents; arcp;
				    arcp = arcp->arc_parentlist) {
					if (arcp->arc_parentp == memberp)
						continue;

					if (arcp->arc_parentp->cycleno ==
									cycle) {
					    cyclenlp->selfcalls +=
							arcp->arc_count;
					} else
					    cyclenlp->ncall += arcp->arc_count;
				}
			}
		}
	}
}


/*
 *	check if any parent of this child
 *	(or outside parents of this cycle)
 *	have their print flags on and set the
 *	print flag of the child (cycle) appropriately.
 *	similarly, deal with propagation fractions from parents.
 */
static void
inheritflags(nltype *childp)
{
	nltype	*headp;
	arctype	*arcp;
	nltype	*parentp;
	nltype	*memp;

	headp = childp->cyclehead;
	if (childp == headp) {
		/*
		 *	just a regular child, check its parents
		 */
		childp->printflag = FALSE;
		childp->propfraction = 0.0;
		for (arcp = childp->parents; arcp;
		    arcp = arcp->arc_parentlist) {
			parentp = arcp->arc_parentp;
			if (childp == parentp) {
				continue;
			}
			childp->printflag |= parentp->printflag;
			/*
			 *	if the child was never actually called
			 *	(e.g. this arc is static (and all others
			 *	are, too)) no time propagates along this arc.
			 */
			if (childp->ncall) {
				childp->propfraction += parentp->propfraction
				    * (((double)arcp->arc_count)
				    / ((double)childp->ncall));
			}
		}
	} else {
		/*
		 *	its a member of a cycle, look at all parents from
		 *	outside the cycle
		 */
		headp->printflag = FALSE;
		headp->propfraction = 0.0;
		for (memp = headp->cnext; memp; memp = memp->cnext) {
			for (arcp = memp->parents; arcp;
			    arcp = arcp->arc_parentlist) {
				if (arcp->arc_parentp->cyclehead == headp) {
					continue;
				}
				parentp = arcp->arc_parentp;
				headp->printflag |= parentp->printflag;
				/*
				 *	if the cycle was never actually called
				 *	(e.g. this arc is static (and all
				 *	others are, too)) no time propagates
				 *	along this arc.
				 */
				if (headp->ncall) {
					headp->propfraction +=
					    parentp->propfraction
					    * (((double)arcp->arc_count)
					    / ((double)headp->ncall));
				}
			}
		}
		for (memp = headp; memp; memp = memp->cnext) {
			memp->printflag = headp->printflag;
			memp->propfraction = headp->propfraction;
		}
	}
}


/*
 * check here if *any* of its parents is printable
 * then return true else return false
 */
static int
check_ancestors(nltype *siblingp)
{
	arctype *parentsp;
	if (!siblingp->parents)
		return (1);
	for (parentsp = siblingp->parents; parentsp;
	    parentsp = parentsp->arc_parentlist) {
		if (parentsp->arc_parentp->printflag)
			return (1);
	}
	return (0);
}


/*
 * check if the parents it passes time are *all* on
 * the Elist in which case we do not pass the time
 */
static int
check_parents(nltype *siblingp)
{
	arctype *parentsp;
	if (!siblingp->parents)
		return (1);
	for (parentsp = siblingp->parents; parentsp;
	    parentsp = parentsp->arc_parentlist) {
		if (!onlist(Elist, parentsp->arc_parentp->name))
			return (1);
	}
	return (0);
}


/*
 *	in one top to bottom pass over the topologically sorted namelist
 *	propagate:
 *		printflag as the union of parents' printflags
 *		propfraction as the sum of fractional parents' propfractions
 *	and while we're here, sum time for functions.
 */
static void
doflags(void)
{
	int	index;
	nltype	*childp;
	nltype	*oldhead;

	oldhead = 0;
	for (index = total_names - 1; index >= 0; index -= 1) {
		childp = topsortnlp[index];
		/*
		 *	if we haven't done this function or cycle,
		 *	inherit things from parent.
		 *	this way, we are linear in the number of arcs
		 *	since we do all members of a cycle (and the
		 *	cycle itself) as we hit the first member
		 *	of the cycle.
		 */
		if (childp->cyclehead != oldhead) {
			oldhead = childp->cyclehead;
			inheritflags(childp);
		}
#ifdef DEBUG
		if (debug & PROPDEBUG) {
			(void) printf("[doflags] ");
			printname(childp);
			(void) printf(
			    " inherits printflag %d and propfraction %f\n",
			    childp->printflag, childp->propfraction);
		}
#endif /* DEBUG */
		if (!childp->printflag) {
			bool	on_flist;
			/*
			 *	printflag is off
			 *	it gets turned on by
			 *	being on -f list,
			 *	or there not being any -f list
			 *	and not being on -e list.
			 */
			if (((on_flist = onlist(flist, childp->name)) != 0) ||
			    (!fflag && !onlist(elist, childp->name))) {
				if (on_flist || check_ancestors(childp))
					childp->printflag = TRUE;
			}
		} else {
			/*
			 *	this function has printing parents:
			 *	maybe someone wants to shut it up
			 *	by putting it on -e list.  (but favor -f
			 *	over -e)
			 */
			if ((!onlist(flist, childp->name)) &&
			    onlist(elist, childp->name)) {
				childp->printflag = FALSE;
			}
		}
		if (childp->propfraction == 0.0) {
			/*
			 *	no parents to pass time to.
			 *	collect time from children if
			 *	its on -F list,
			 *	or there isn't any -F list and its not
			 *	on -E list.
			 */
			if (onlist(Flist, childp->name) ||
			    (!Fflag && !onlist(Elist, childp->name))) {
				childp->propfraction = 1.0;
			}
		} else {
			/*
			 *	it has parents to pass time to,
			 *	but maybe someone wants to shut it up
			 *	by putting it on -E list.  (but favor -F
			 *	over -E)
			 */
			if (!onlist(Flist, childp->name) &&
			    onlist(Elist, childp->name)) {
				if (check_parents(childp))
					childp->propfraction = 0.0;
			}
		}
		childp->propself = childp->time * childp->propfraction;
		printtime += childp->propself;
#ifdef DEBUG
		if (debug & PROPDEBUG) {
			(void) printf("[doflags] ");
			printname(childp);
			(void) printf(" ends up with printflag %d and "
			    "propfraction %f\n",
			    childp->printflag, childp->propfraction);
			(void) printf("time %f propself %f printtime %f\n",
			    childp->time, childp->propself, printtime);
		}
#endif /* DEBUG */
	}
}


nltype **
doarcs(void)
{
	nltype	*parentp, **timesortnlp;
	arctype	*arcp;
	long	i, index;

	extern mod_info_t	modules;
	mod_info_t		*mi;

	/*
	 *	initialize various things:
	 *	    zero out child times.
	 *	    count self-recursive calls.
	 *	    indicate that nothing is on cycles.
	 */
	for (mi = &modules; mi; mi = mi->next) {
		for (parentp = mi->nl; parentp < mi->npe; parentp++) {
			parentp->childtime = 0.0;
			arcp = arclookup(parentp, parentp);
			if (arcp != 0) {
				parentp->ncall -= arcp->arc_count;
				parentp->selfcalls = arcp->arc_count;
			} else {
				parentp->selfcalls = 0;
			}
			parentp->propfraction = 0.0;
			parentp->propself = 0.0;
			parentp->propchild = 0.0;
			parentp->printflag = FALSE;
			parentp->toporder = DFN_NAN;
			parentp->cycleno = 0;
			parentp->cyclehead = parentp;
			parentp->cnext = 0;

			/*
			 * Inspecting text space is valid only for
			 * the program executable.
			 */
			if (cflag && (mi == &modules)) {
				findcalls(
					parentp,
					parentp->value,
					parentp->value + parentp->sz);
			}
		}
	}

	/*
	 *	topologically order things
	 *	if any node is unnumbered,
	 *	    number it and any of its descendents.
	 */
	for (mi = &modules; mi; mi = mi->next) {
		for (parentp = mi->nl; parentp < mi->npe; parentp++) {
			if (parentp->toporder == DFN_NAN) {
				dfn(parentp);
			}
		}
	}

	/*
	 *	link together nodes on the same cycle
	 */
	cyclelink();
	/*
	 *	Sort the symbol tables in reverse topological order
	 */
	topsortnlp = (nltype **) calloc(total_names, sizeof (nltype *));
	if (topsortnlp == (nltype **) 0) {
		(void) fprintf(stderr,
		    "[doarcs] ran out of memory for topo sorting\n");
	}
	index = 0;
	for (mi = &modules; mi; mi = mi->next) {
		for (i = 0; i < mi->nname; i++)
		    topsortnlp[index++] = &(mi->nl[i]);
	}

	qsort(topsortnlp, total_names, sizeof (nltype *), topcmp);
#ifdef DEBUG
	if (debug & DFNDEBUG) {
		(void) printf("[doarcs] topological sort listing\n");
		for (index = 0; index < total_names; index += 1) {
			(void) printf("[doarcs] ");
			(void) printf("%d:", topsortnlp[ index ]->toporder);
			printname(topsortnlp[ index ]);
			(void) printf("\n");
		}
	}
#endif /* DEBUG */
	/*
	 *	starting from the topological top,
	 *	propagate print flags to children.
	 *	also, calculate propagation fractions.
	 *	this happens before time propagation
	 *	since time propagation uses the fractions.
	 */
	doflags();
	/*
	 *	starting from the topological bottom,
	 *	propogate children times up to parents.
	 */
	dotime();
	/*
	 *	Now, sort by propself + propchild.
	 *	sorting both the regular function names
	 *	and cycle headers.
	 */
	timesortnlp = (nltype **) calloc(total_names + ncycle,
							sizeof (nltype *));
	if (timesortnlp == (nltype **) 0) {
		(void) fprintf(stderr,
		    "%s: ran out of memory for sorting\n", whoami);
	}

	index = 0;
	for (mi = &modules; mi; mi = mi->next) {
		for (i = 0; i < mi->nname; i++)
		    timesortnlp[index++] = &(mi->nl[i]);
	}

	for (index = 1; index <= ncycle; index++)
		timesortnlp[total_names+index-1] = &cyclenl[index];

	qsort(timesortnlp, total_names + ncycle, sizeof (nltype *), totalcmp);

	for (index = 0; index < total_names + ncycle; index++)
		timesortnlp[index]->index = index + 1;

	return (timesortnlp);
}
