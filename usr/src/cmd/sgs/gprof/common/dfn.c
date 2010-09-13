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

#include <stdio.h>
#include "gprof.h"

#define	DFN_DEPTH	100

struct dfnstruct {
	nltype	*nlentryp;
	int	cycletop;
};

typedef struct dfnstruct	dfntype;

dfntype	*dfn_stack = NULL;
int	dfn_depth = 0;
int	dfn_sz = 0;

int	dfn_counter = DFN_NAN;

/*
 *	given this parent, depth first number its children.
 */
void
dfn(nltype *parentp)
{
	arctype	*arcp;

#ifdef DEBUG
	if (debug & DFNDEBUG) {
		(void) printf("[dfn] dfn(");
		printname(parentp);
		(void) printf(")\n");
	}
#endif /* DEBUG */

	if (!dfn_stack) {
		dfn_sz = DFN_DEPTH;
		dfn_stack = (dfntype *) malloc(dfn_sz * sizeof (dfntype));
		if (!dfn_stack) {
			(void) fprintf(stderr,
			    "fatal: can't malloc %d objects\n", dfn_sz);
			exit(1);
		}
	}

	/*
	 *	if we're already numbered, no need to look any furthur.
	 */
	if (dfn_numbered(parentp))
		return;

	/*
	 *	if we're already busy, must be a cycle
	 */
	if (dfn_busy(parentp)) {
		dfn_findcycle(parentp);
		return;
	}

	/*
	 *	visit yourself before your children
	 */
	dfn_pre_visit(parentp);

	/*
	 *	visit children
	 */
	for (arcp = parentp->children; arcp; arcp = arcp->arc_childlist)
		dfn(arcp->arc_childp);

	/*
	 *	visit yourself after your children
	 */
	dfn_post_visit(parentp);
}

/*
 *	push a parent onto the stack and mark it busy
 */
void
dfn_pre_visit(nltype *parentp)
{

	if (!dfn_stack) {
		dfn_sz = DFN_DEPTH;
		dfn_stack = (dfntype *) malloc(dfn_sz * sizeof (dfntype));
		if (!dfn_stack) {
			(void) printf("fatal: can't malloc %d objects\n",
			    dfn_sz);
			exit(1);
		}
	}

	dfn_depth += 1;

	if (dfn_depth >= dfn_sz) {
		dfn_sz += DFN_DEPTH;
		dfn_stack = (dfntype *) realloc(dfn_stack,
		    dfn_sz * sizeof (dfntype));

		if (!dfn_stack) {
			(void) fprintf(stderr,
			    "fatal: can't realloc %d objects\n", dfn_sz);
			exit(1);
		}
	}

	dfn_stack[dfn_depth].nlentryp = parentp;
	dfn_stack[dfn_depth].cycletop = dfn_depth;
	parentp->toporder = DFN_BUSY;

#ifdef DEBUG
	if (debug & DFNDEBUG) {
		(void) printf("[dfn_pre_visit]\t\t%d:", dfn_depth);
		printname(parentp);
		(void) printf("\n");
	}
#endif /* DEBUG */
}

/*
 *	are we already numbered?
 */
bool
dfn_numbered(nltype *childp)
{
	return (childp->toporder != DFN_NAN && childp->toporder != DFN_BUSY);
}

/*
 *	are we already busy?
 */
bool
dfn_busy(nltype *childp)
{
	if (childp->toporder == DFN_NAN)
		return (FALSE);

	return (TRUE);
}

void
dfn_findcycle(nltype *childp)
{
	int		cycletop;
	nltype	*cycleheadp;
	nltype	*tailp;
	int		index;

	for (cycletop = dfn_depth; cycletop > 0; cycletop -= 1) {
		cycleheadp = dfn_stack[cycletop].nlentryp;
		if (childp == cycleheadp)
			break;

		if (childp->cyclehead != childp &&
		    childp->cyclehead == cycleheadp)
			break;
	}

	if (cycletop <= 0) {
		/*
		 * don't report non existent functions
		 */
		if (childp->value) {
			(void) fprintf(stderr,
			    "[dfn_findcycle] couldn't find head "
			    "of cycle for %s\n", childp->name);
			return;
		}
	}

#ifdef DEBUG
	if (debug & DFNDEBUG) {
		(void) printf("[dfn_findcycle] dfn_depth %d cycletop %d ",
		    dfn_depth, cycletop);
		printname(cycleheadp);
		(void) printf("\n");
	}
#endif /* DEBUG */

	if (cycletop == dfn_depth) {
		/*
		 *	this is previous function, e.g. this calls itself
		 *	sort of boring
		 */
		dfn_self_cycle(childp);
	} else {
		/*
		 *	glom intervening functions that aren't already
		 *	glommed into this cycle.
		 *	things have been glommed when their cyclehead field
		 *	points to the head of the cycle they are glommed into.
		 */
		for (tailp = cycleheadp; tailp->cnext; tailp = tailp->cnext) {
			/* void: chase down to tail of things already glommed */
#ifdef DEBUG
			if (debug & DFNDEBUG) {
				(void) printf("[dfn_findcycle] tail ");
				printname(tailp);
				(void) printf("\n");
			}
#endif /* DEBUG */
		}

		/*
		 *	if what we think is the top of the cycle
		 *	has a cyclehead field, then it's not really the
		 *	head of the cycle, which is really what we want
		 */
		if (cycleheadp->cyclehead != cycleheadp) {
			cycleheadp = cycleheadp->cyclehead;
#ifdef DEBUG
			if (debug & DFNDEBUG) {
				(void) printf("[dfn_findcycle] new cyclehead ");
				printname(cycleheadp);
				(void) printf("\n");
			}
#endif /* DEBUG */
		}

		for (index = cycletop + 1; index <= dfn_depth; index += 1) {

			childp = dfn_stack[index].nlentryp;
			if (childp->cyclehead == childp) {
				/*
				 *	not yet glommed anywhere, glom it
				 *	and fix any children it has glommed
				 */
				tailp->cnext = childp;
				childp->cyclehead = cycleheadp;
#ifdef DEBUG
				if (debug & DFNDEBUG) {
					(void) printf(
					    "[dfn_findcycle] glomming ");
					printname(childp);
					(void) printf(" onto ");
					printname(cycleheadp);
					(void) printf("\n");
				}
#endif /* DEBUG */
				for (tailp = childp; tailp->cnext;
				    tailp = tailp->cnext) {
					tailp->cnext->cyclehead = cycleheadp;
#ifdef DEBUG
					if (debug & DFNDEBUG) {
						(void) printf("[dfn_findcycle]"
						    " and its tail ");
						printname(tailp->cnext);
						(void) printf(" onto ");
						printname(cycleheadp);
						(void) printf("\n");
					}
#endif /* DEBUG */
				}
			} else if (childp->cyclehead != cycleheadp) {
				(void) fprintf(stderr, "[dfn_busy] glommed,"
				    " but not to cyclehead\n");
			}
		}
	}
}

/*
 *	deal with self-cycles
 *	for lint: ARGSUSED
 */
/* ARGSUSED */
void
dfn_self_cycle(nltype *parentp)
{
	/*
	 *	since we are taking out self-cycles elsewhere
	 *	no need for the special case, here.
	 */
#ifdef DEBUG
	if (debug & DFNDEBUG) {
		(void) printf("[dfn_self_cycle] ");
		printname(parentp);
		(void) printf("\n");
	}
#endif /* DEBUG */
}

/*
 *	visit a node after all its children
 *	[MISSING: an explanation]
 *	and pop it off the stack
 */
void
dfn_post_visit(nltype *parentp)
{
	nltype	*memberp;

#ifdef DEBUG
	if (debug & DFNDEBUG) {
		(void) printf("[dfn_post_visit]\t%d: ", dfn_depth);
		printname(parentp);
		(void) printf("\n");
	}
#endif /* DEBUG */
	/*
	 *	number functions and things in their cycles
	 *	unless the function is itself part of a cycle
	 */
	if (parentp->cyclehead == parentp) {
		dfn_counter += 1;

		for (memberp = parentp; memberp; memberp = memberp->cnext) {

			memberp->toporder = dfn_counter;
#ifdef DEBUG
			if (debug & DFNDEBUG) {
				(void) printf("[dfn_post_visit]\t\tmember ");
				printname(memberp);
				(void) printf(" -> toporder = %d\n",
				    dfn_counter);
			}
#endif /* DEBUG */
		}
#ifdef DEBUG
	} else {
		if (debug & DFNDEBUG)
			(void) printf(
			    "[dfn_post_visit]\t\tis part of a cycle\n");
#endif /* DEBUG */
	}
	dfn_depth -= 1;
}
