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
 *
 * Copyright 2018 Jason King
 * Copyright 2018, Joyent, Inc.
 */

#include <ctype.h>
#include <string.h>
#include <sys/param.h>
#include <stdlib.h>
#include "conv.h"
#include "gprof.h"

void print_demangled_name(int, nltype *);
static void stripped_name(char **, size_t *, nltype **);

extern long hz;

/*
 * Symbols that must never be printed, no matter what.
 */
char *splsym[] = {
	PRF_ETEXT,
	PRF_EXTSYM,
	PRF_MEMTERM,
	NULL
};

static bool is_special_sym(nltype *nlp);

const char *
demangled_name(nltype *selfp)
{
	if (!Cflag)
		return (selfp->name);

	return (conv_demangle_name(selfp->name));
}

void
printprof(void)
{
	nltype	*np;
	nltype	**sortednlp;
	int	i, index;
	int	print_count = number_funcs_toprint;
	bool	print_flag = TRUE;
	mod_info_t	*mi;

	actime = 0.0;
	(void) printf("\f\n");
	flatprofheader();

	/*
	 *	Sort the symbol table in by time
	 */
	sortednlp = (nltype **) calloc(total_names, sizeof (nltype *));
	if (sortednlp == (nltype **) 0) {
		(void) fprintf(stderr,
		    "[printprof] ran out of memory for time sorting\n");
	}

	index = 0;
	for (mi = &modules; mi; mi = mi->next) {
		for (i = 0; i < mi->nname; i++)
			sortednlp[index++] = &(mi->nl[i]);
	}

	qsort(sortednlp, total_names, sizeof (nltype *), timecmp);

	for (index = 0; (index < total_names) && print_flag; index += 1) {
		np = sortednlp[index];
		flatprofline(np);
		if (nflag) {
			if (--print_count == 0)
				print_flag = FALSE;
		}
	}
	actime = 0.0;
	free(sortednlp);
}

int
timecmp(const void *arg1, const void *arg2)
{
	nltype **npp1 = (nltype **)arg1;
	nltype **npp2 = (nltype **)arg2;
	double	timediff;
	long	calldiff;

	timediff = (*npp2)->time - (*npp1)->time;

	if (timediff > 0.0)
		return (1);

	if (timediff < 0.0)
		return (-1);

	calldiff = (*npp2)->ncall - (*npp1)->ncall;

	if (calldiff > 0)
		return (1);

	if (calldiff < 0)
		return (-1);

	return (strcmp((*npp1)->name, (*npp2)->name));
}

/*
 *	header for flatprofline
 */
void
flatprofheader()
{

	if (bflag)
		printblurb(FLAT_BLURB);

	if (old_style) {
		(void) printf(
		    "\ngranularity: each sample hit covers %d byte(s)",
		    (long)scale * sizeof (UNIT));
		if (totime > 0.0) {
			(void) printf(" for %.2f%% of %.2f seconds\n\n",
			    100.0/totime, totime / hz);
		} else {
			(void) printf(" no time accumulated\n\n");
			/*
			 * this doesn't hurt since all the numerators will
			 * be zero.
			 */
			totime = 1.0;
		}
	}

	(void) printf("%5.5s %10.10s %8.8s %8.8s %8.8s %8.8s %-8.8s\n",
	    "% ", "cumulative", "self ", "", "self ", "total ", "");
	(void) printf("%5.5s %10.10s %8.8s %8.8s %8.8s %8.8s %-8.8s\n",
	    "time", "seconds ", "seconds", "calls",
	    "ms/call", "ms/call", "name");
}

void
flatprofline(nltype *np)
{
	if (zflag == 0 && np->ncall == 0 && np->time == 0)
		return;

	/*
	 * Do not print certain special symbols, like PRF_EXTSYM, etc.
	 * even if zflag was on.
	 */
	if (is_special_sym(np))
		return;

	actime += np->time;

	(void) printf("%5.1f %10.2f %8.2f",
	    100 * np->time / totime, actime / hz, np->time / hz);

	if (np->ncall != 0) {
		(void) printf(" %8lld %8.2f %8.2f  ", np->ncall,
		    1000 * np->time / hz / np->ncall,
		    1000 * (np->time + np->childtime) / hz / np->ncall);
	} else {
		if (!Cflag)
			(void) printf(" %8.8s %8.8s %8.8s ", "", "", "");
		else
			(void) printf(" %8.8s %8.8s %8.8s  ", "", "", "");
	}

	printname(np);

	if (Cflag)
		print_demangled_name(55, np);

	(void) printf("\n");
}

void
gprofheader()
{

	if (bflag)
		printblurb(CALLG_BLURB);

	if (old_style) {

		(void) printf(
		    "\ngranularity: each sample hit covers %d byte(s)",
		    (long)scale * sizeof (UNIT));

		if (printtime > 0.0) {
			(void) printf(" for %.2f%% of %.2f seconds\n\n",
			    100.0/printtime, printtime / hz);
		} else {
			(void) printf(" no time propagated\n\n");
			/*
			 * this doesn't hurt, since all the numerators
			 * will be 0.0
			 */
			printtime = 1.0;
		}
	} else {
		(void) printf(
		    "\ngranularity: each pc-hit is considered 1 tick");
		if (hz != 1) {
			(void) printf(" (@ %4.3f seconds per tick)",
			    (double)1.0 / hz);
		}
		(void) puts("\n\n");
	}

	(void) printf("%6.6s %5.5s %7.7s %11.11s %7.7s/%-7.7s     %-8.8s\n",
	    "", "", "", "", "called", "total", "parents");
	(void) printf("%-6.6s %5.5s %7.7s %11.11s %7.7s+%-7.7s %-8.8s\t%5.5s\n",
	    "index", "%time", "self", "descendents",
	    "called", "self", "name", "index");
	(void) printf("%6.6s %5.5s %7.7s %11.11s %7.7s/%-7.7s     %-8.8s\n",
	    "", "", "", "", "called", "total", "children");
	(void) printf("\n");
}

void
gprofline(nltype *np)
{
	char	kirkbuffer[BUFSIZ];

	(void) sprintf(kirkbuffer, "[%d]", np->index);
	(void) printf("%-6.6s %5.1f %7.2f %11.2f", kirkbuffer,
	    100 * (np->propself + np->propchild) / printtime,
	    np->propself / hz, np->propchild / hz);

	if ((np->ncall + np->selfcalls) != 0) {
		(void) printf(" %7lld", np->ncall);

		if (np->selfcalls != 0)
			(void) printf("+%-7lld ", np->selfcalls);
		else
			(void) printf(" %7.7s ", "");
	} else {
		(void) printf(" %7.7s %7.7s ", "", "");
	}

	printname(np);

	if (Cflag)
		print_demangled_name(50, np);

	(void) printf("\n");
}

static bool
is_special_sym(nltype *nlp)
{
	int	i;

	if (nlp->name == NULL)
		return (FALSE);

	for (i = 0;  splsym[i]; i++)
		if (strcmp(splsym[i], nlp->name) == 0)
			return (TRUE);

	return (FALSE);
}

void
printgprof(nltype **timesortnlp)
{
	int	index;
	nltype	*parentp;
	int	print_count = number_funcs_toprint;
	bool	count_flag = TRUE;

	/*
	 * Print out the structured profiling list
	 */
	gprofheader();

	for (index = 0; index < total_names + ncycle && count_flag; index++) {
		parentp = timesortnlp[index];
		if (zflag == 0 && parentp->ncall == 0 &&
		    parentp->selfcalls == 0 && parentp->propself == 0 &&
		    parentp -> propchild == 0)
			continue;

		if (!parentp->printflag)
			continue;

		/*
		 * Do not print certain special symbols, like PRF_EXTSYM, etc.
		 * even if zflag was on.
		 */
		if (is_special_sym(parentp))
			continue;

		if (parentp->name == 0 && parentp->cycleno != 0) {
			/*
			 *	cycle header
			 */
			printcycle(parentp);
			printmembers(parentp);
		} else {
			printparents(parentp);
			gprofline(parentp);
			printchildren(parentp);
		}

		(void) printf("\n");
		(void) printf(
		    "-----------------------------------------------\n");
		(void) printf("\n");

		if (nflag) {
			--print_count;
			if (print_count == 0)
				count_flag = FALSE;
		}
	}
	free(timesortnlp);
}

/*
 *	sort by decreasing propagated time
 *	if times are equal, but one is a cycle header,
 *		say that's first (e.g. less, i.e. -1).
 *	if one's name doesn't have an underscore and the other does,
 *		say the one is first.
 *	all else being equal, sort by names.
 */
int
totalcmp(const void *arg1, const void *arg2)
{
	nltype **npp1 = (nltype **)arg1;
	nltype **npp2 = (nltype **)arg2;
	nltype	*np1 = *npp1;
	nltype	*np2 = *npp2;
	double	diff;

	diff = (np1->propself + np1->propchild) -
	    (np2->propself + np2->propchild);

	if (diff < 0.0)
		return (1);
	if (diff > 0.0)
		return (-1);
	if (np1->name == 0 && np1->cycleno != 0)
		return (-1);
	if (np2->name == 0 && np2->cycleno != 0)
		return (1);
	if (np1->name == 0)
		return (-1);
	if (np2->name == 0)
		return (1);

	if (*(np1->name) != '_' && *(np2->name) == '_')
		return (-1);
	if (*(np1->name) == '_' && *(np2->name) != '_')
		return (1);
	if (np1->ncall > np2->ncall)
		return (-1);
	if (np1->ncall < np2->ncall)
		return (1);
	return (strcmp(np1->name, np2->name));
}

void
printparents(nltype *childp)
{
	nltype	*parentp;
	arctype	*arcp;
	nltype	*cycleheadp;

	if (childp->cyclehead != 0)
		cycleheadp = childp -> cyclehead;
	else
		cycleheadp = childp;

	if (childp->parents == 0) {
		(void) printf("%6.6s %5.5s %7.7s %11.11s %7.7s %7.7s"
		    "     <spontaneous>\n", "", "", "", "", "", "");
		return;
	}

	sortparents(childp);

	for (arcp = childp->parents; arcp; arcp = arcp->arc_parentlist) {
		parentp = arcp -> arc_parentp;
		if (childp == parentp || (childp->cycleno != 0 &&
		    parentp->cycleno == childp->cycleno)) {
			/*
			 *	selfcall or call among siblings
			 */
			(void) printf(
			    "%6.6s %5.5s %7.7s %11.11s %7lld %7.7s     ",
			    "", "", "", "", arcp->arc_count, "");
			printname(parentp);

			if (Cflag)
				print_demangled_name(54, parentp);

			(void) printf("\n");
		} else {
			/*
			 *	regular parent of child
			 */
			(void) printf(
			    "%6.6s %5.5s %7.2f %11.2f %7lld/%-7lld     ", "",
			    "", arcp->arc_time / hz, arcp->arc_childtime / hz,
			    arcp->arc_count, cycleheadp->ncall);
			printname(parentp);

			if (Cflag)
				print_demangled_name(54, parentp);

			(void) printf("\n");
		}
	}
}

void
printchildren(nltype *parentp)
{
	nltype	*childp;
	arctype	*arcp;

	sortchildren(parentp);

	for (arcp = parentp->children; arcp; arcp = arcp->arc_childlist) {
		childp = arcp->arc_childp;
		if (childp == parentp || (childp->cycleno != 0 &&
		    childp->cycleno == parentp->cycleno)) {
			/*
			 * self call or call to sibling
			 */
			(void) printf(
			    "%6.6s %5.5s %7.7s %11.11s %7lld %7.7s     ",
			    "", "", "", "", arcp->arc_count, "");
			printname(childp);

			if (Cflag)
				print_demangled_name(54, childp);

			(void) printf("\n");
		} else {
			/*
			 *	regular child of parent
			 */
			if (childp->cyclehead)
				(void) printf("%6.6s %5.5s %7.2f %11.2f "
				    "%7lld/%-7lld     ", "", "",
				    arcp->arc_time / hz,
				    arcp->arc_childtime / hz, arcp->arc_count,
				    childp->cyclehead->ncall);
			else
				(void) printf("%6.6s %5.5s %7.2f %11.2f "
				    "%7lld %7.7s    ",
				    "", "", arcp->arc_time / hz,
				    arcp->arc_childtime / hz, arcp->arc_count,
				    "");

			printname(childp);

			if (Cflag)
				print_demangled_name(54, childp);

			(void) printf("\n");
		}
	}
}

void
printname(nltype *selfp)
{
	const char  *c;
	c = demangled_name(selfp);

	if (selfp->name != 0) {
		(void) printf("%s", c);

#ifdef DEBUG
		if (debug & DFNDEBUG)
			(void) printf("{%d} ", selfp->toporder);

		if (debug & PROPDEBUG)
			(void) printf("%5.2f%% ", selfp->propfraction);
#endif /* DEBUG */
	}

	if (selfp->cycleno != 0)
		(void) printf("\t<cycle %d>", selfp->cycleno);

	if (selfp->index != 0) {
		if (selfp->printflag)
			(void) printf(" [%d]", selfp->index);
		else
			(void) printf(" (%d)", selfp->index);
	}

	if (c != selfp->name)
		free((void *)c);
}

void
print_demangled_name(int n, nltype *selfp)
{
	char *c = (char *)demangled_name(selfp);
	int i;

	if (c == selfp->name)
		return;

	(void) printf("\n");
	for (i = 1; i < n; i++)
		(void) printf(" ");
	(void) printf("[%s]", selfp->name);

	free(c);
}

void
sortchildren(nltype *parentp)
{
	arctype	*arcp;
	arctype	*detachedp;
	arctype	sorted;
	arctype	*prevp;

	/*
	 *	unlink children from parent,
	 *	then insertion sort back on to sorted's children.
	 *	    *arcp	the arc you have detached and are inserting.
	 *	    *detachedp	the rest of the arcs to be sorted.
	 *	    sorted	arc list onto which you insertion sort.
	 *	    *prevp	arc before the arc you are comparing.
	 */
	sorted.arc_childlist = 0;

	/* LINTED: warning: assignment operator */
	for ((arcp = parentp->children) && (detachedp = arcp->arc_childlist);
	    arcp;
	    /* LINTED: warning: assignment operator */
	    (arcp = detachedp) && (detachedp = detachedp->arc_childlist)) {
		/*
		 *	consider *arcp as disconnected
		 *	insert it into sorted
		 */
		for (prevp = &sorted; prevp->arc_childlist;
		    prevp = prevp->arc_childlist) {
			if (arccmp(arcp, prevp->arc_childlist) != LESSTHAN)
				break;
		}

		arcp->arc_childlist = prevp->arc_childlist;
		prevp->arc_childlist = arcp;
	}

	/*
	 *	reattach sorted children to parent
	 */
	parentp->children = sorted.arc_childlist;
}

void
sortparents(nltype *childp)
{
	arctype	*arcp;
	arctype	*detachedp;
	arctype	sorted;
	arctype	*prevp;

	/*
	 *	unlink parents from child,
	 *	then insertion sort back on to sorted's parents.
	 *	    *arcp	the arc you have detached and are inserting.
	 *	    *detachedp	the rest of the arcs to be sorted.
	 *	    sorted	arc list onto which you insertion sort.
	 *	    *prevp	arc before the arc you are comparing.
	 */
	sorted.arc_parentlist = 0;

	/* LINTED: warning: assignment operator */
	for ((arcp = childp->parents) && (detachedp = arcp->arc_parentlist);
	    arcp;
	    /* LINTED: warning: assignment operator */
	    (arcp = detachedp) && (detachedp = detachedp->arc_parentlist)) {
		/*
		 *	consider *arcp as disconnected
		 *	insert it into sorted
		 */
		for (prevp = &sorted; prevp->arc_parentlist;
		    prevp = prevp->arc_parentlist) {
			if (arccmp(arcp, prevp->arc_parentlist) != GREATERTHAN)
				break;
		}
		arcp->arc_parentlist = prevp->arc_parentlist;
		prevp->arc_parentlist = arcp;
	}

	/*
	 *	reattach sorted arcs to child
	 */
	childp->parents = sorted.arc_parentlist;
}

void
printcycle(nltype *cyclep)
{
	char	kirkbuffer[BUFSIZ];

	(void) sprintf(kirkbuffer, "[%d]", cyclep->index);
	(void) printf("%-6.6s %5.1f %7.2f %11.2f %7lld", kirkbuffer,
	    100 * (cyclep->propself + cyclep->propchild) / printtime,
	    cyclep -> propself / hz, cyclep -> propchild / hz,
	    cyclep -> ncall);

	if (cyclep->selfcalls != 0)
		(void) printf("+%-7lld", cyclep->selfcalls);
	else
		(void) printf(" %7.7s", "");

	(void) printf(" <cycle %d as a whole>\t[%d]\n", cyclep->cycleno,
	    cyclep->index);
}

/*
 *	print the members of a cycle
 */
void
printmembers(nltype *cyclep)
{
	nltype	*memberp;

	sortmembers(cyclep);

	for (memberp = cyclep->cnext; memberp; memberp = memberp->cnext) {
		(void) printf("%6.6s %5.5s %7.2f %11.2f %7lld", "", "",
		    memberp->propself / hz, memberp->propchild / hz,
		    memberp->ncall);

		if (memberp->selfcalls != 0)
			(void) printf("+%-7lld", memberp->selfcalls);
		else
			(void) printf(" %7.7s", "");

		(void) printf("     ");
		printname(memberp);
		if (Cflag)
			print_demangled_name(54, memberp);
		(void) printf("\n");
	}
}

/*
 * sort members of a cycle
 */
void
sortmembers(nltype *cyclep)
{
	nltype	*todo;
	nltype	*doing;
	nltype	*prev;

	/*
	 *	detach cycle members from cyclehead,
	 *	and insertion sort them back on.
	 */
	todo = cyclep->cnext;
	cyclep->cnext = 0;

	/* LINTED: warning: assignment operator */
	for ((doing = todo) && (todo = doing->cnext);
	    doing;
	    /* LINTED: warning: assignment operator */
	    (doing = todo) && (todo = doing->cnext)) {
		for (prev = cyclep; prev->cnext; prev = prev->cnext) {
			if (membercmp(doing, prev->cnext) == GREATERTHAN)
				break;
		}
		doing->cnext = prev->cnext;
		prev->cnext = doing;
	}
}

/*
 *	major sort is on propself + propchild,
 *	next is sort on ncalls + selfcalls.
 */
int
membercmp(nltype *this, nltype *that)
{
	double	thistime = this->propself + this->propchild;
	double	thattime = that->propself + that->propchild;
	actype	thiscalls = this->ncall + this->selfcalls;
	actype	thatcalls = that->ncall + that->selfcalls;

	if (thistime > thattime)
		return (GREATERTHAN);

	if (thistime < thattime)
		return (LESSTHAN);

	if (thiscalls > thatcalls)
		return (GREATERTHAN);

	if (thiscalls < thatcalls)
		return (LESSTHAN);

	return (EQUALTO);
}

/*
 *	compare two arcs to/from the same child/parent.
 *	- if one arc is a self arc, it's least.
 *	- if one arc is within a cycle, it's less than.
 *	- if both arcs are within a cycle, compare arc counts.
 *	- if neither arc is within a cycle, compare with
 *		arc_time + arc_childtime as major key
 *		arc count as minor key
 */
int
arccmp(arctype *thisp, arctype *thatp)
{
	nltype	*thisparentp = thisp->arc_parentp;
	nltype	*thischildp = thisp->arc_childp;
	nltype	*thatparentp = thatp->arc_parentp;
	nltype	*thatchildp = thatp->arc_childp;
	double	thistime;
	double	thattime;

#ifdef DEBUG
	if (debug & TIMEDEBUG) {
		(void) printf("[arccmp] ");
		printname(thisparentp);
		(void) printf(" calls ");
		printname(thischildp);
		(void) printf(" %f + %f %lld/%lld\n", thisp->arc_time,
		    thisp->arc_childtime, thisp->arc_count,
		    thischildp->ncall);
		(void) printf("[arccmp] ");
		printname(thatparentp);
		(void) printf(" calls ");
		printname(thatchildp);
		(void) printf(" %f + %f %lld/%lld\n", thatp->arc_time,
		    thatp->arc_childtime, thatp->arc_count,
		    thatchildp->ncall);
		(void) printf("\n");
	}
#endif /* DEBUG */

	if (thisparentp == thischildp) {
		/*
		 * this is a self call
		 */
		return (LESSTHAN);
	}

	if (thatparentp == thatchildp) {
		/*
		 * that is a self call
		 */
		return (GREATERTHAN);
	}

	if (thisparentp->cycleno != 0 && thischildp->cycleno != 0 &&
	    thisparentp->cycleno == thischildp->cycleno) {
		/*
		 * this is a call within a cycle
		 */
		if (thatparentp->cycleno != 0 && thatchildp->cycleno != 0 &&
		    thatparentp->cycleno == thatchildp->cycleno) {
			/*
			 * that is a call within the cycle, too
			 */
			if (thisp->arc_count < thatp->arc_count)
				return (LESSTHAN);

			if (thisp->arc_count > thatp->arc_count)
				return (GREATERTHAN);

			return (EQUALTO);
		} else {
			/*
			 * that isn't a call within the cycle
			 */
			return (LESSTHAN);
		}
	} else {
		/*
		 * this isn't a call within a cycle
		 */
		if (thatparentp->cycleno != 0 && thatchildp->cycleno != 0 &&
		    thatparentp->cycleno == thatchildp->cycleno) {
			/*
			 * that is a call within a cycle
			 */
			return (GREATERTHAN);
		} else {
			/*
			 * neither is a call within a cycle
			 */
			thistime = thisp->arc_time + thisp->arc_childtime;
			thattime = thatp->arc_time + thatp->arc_childtime;

			if (thistime < thattime)
				return (LESSTHAN);

			if (thistime > thattime)
				return (GREATERTHAN);

			if (thisp->arc_count < thatp->arc_count)
				return (LESSTHAN);

			if (thisp->arc_count > thatp->arc_count)
				return (GREATERTHAN);

			return (EQUALTO);
		}
	}
}

void
printblurb(char *blurbname)
{
	FILE	*blurbfile;
	int	input;

	blurbfile = fopen(blurbname, "r");
	if (blurbfile == NULL) {
		perror(blurbname);
		return;
	}

	while ((input = getc(blurbfile)) != EOF)
		(void) putchar(input);

	(void) fclose(blurbfile);
}

static int
namecmp(const void *arg1, const void *arg2)
{
	nltype **npp1 = (nltype **)arg1;
	nltype **npp2 = (nltype **)arg2;

	if (!Cflag)
		return (strcmp((*npp1)->name, (*npp2)->name));
	else {
		static char *s1 = NULL, *s2 = NULL;
		static size_t s1len = 0, s2len = 0;

		stripped_name(&s1, &s1len, npp1);
		stripped_name(&s2, &s2len, npp2);
		return (strcmp(s1, s2));
	}
}

#define	NAME_CHUNK 512
#define	ROUNDLEN(x) (((x) + NAME_CHUNK - 1) / NAME_CHUNK * NAME_CHUNK)
static void
adjust_size(char **pp, size_t *lenp, const char *name)
{
	void *newp;
	size_t nlen = strlen(name);
	size_t buflen;

	if (*lenp > nlen) {
		(void) memset(*pp, '\0', *lenp);
		return;
	}

	buflen = ROUNDLEN(nlen + 1);
	if ((newp = realloc(*pp, buflen)) == NULL) {
		(void) fprintf(stderr,
		    "gprof: out of memory comparing names\n");
		exit(EXIT_FAILURE);
	}
	(void) memset(newp, '\0', buflen);

	*lenp = buflen;
	*pp = newp;
}

static void
stripped_name(char **sp, size_t *slenp, nltype **npp)
{
	const char *name, *d;
	char *c;

	name = d = demangled_name(*npp);
	adjust_size(sp, slenp, name);
	c = *sp;

	while ((*d != '(') && (*d != '\0')) {
		if (*d != ':')
			*c++ = *d++;
		else
			d++;
	}
	*c = '\0';

	if ((*npp)->name != name)
		free((void *)name);
}

/*
 * Checks if the current symbol name is the same as its neighbour and
 * returns TRUE if it is.
 */
static bool
does_clash(nltype **nlp, int ndx, int nnames)
{
	/*
	 * same as previous (if there's one) ?
	 */
	if (ndx && (strcmp(nlp[ndx]->name, nlp[ndx-1]->name) == 0))
		return (TRUE);

	/*
	 * same as next (if there's one) ?
	 */
	if ((ndx < (nnames - 1)) &&
	    (strcmp(nlp[ndx]->name, nlp[ndx+1]->name) == 0)) {
		return (TRUE);
	}

	return (FALSE);
}

void
printmodules()
{
	mod_info_t	*mi;

	(void) printf("\f\nObject modules\n\n");
	for (mi = &modules; mi; mi = mi->next)
		(void) printf(" %d: %s\n", mi->id, mi->name);
}

#define	IDFMT(id)	((id) < 10 ? 1 : 2)
#define	NMFMT(id)	((id) < 10 ? 17 : 16)

void
printindex()
{
	nltype	**namesortnlp;
	nltype	*nlp;
	int	index, nnames, todo, i, j;
	char	peterbuffer[BUFSIZ];
	mod_info_t	*mi;

	/*
	 *	Now, sort regular function name alphabetically
	 *	to create an index.
	 */
	namesortnlp = calloc(total_names + ncycle, sizeof (nltype *));

	if (namesortnlp == NULL)
		(void) fprintf(stderr, "%s: ran out of memory for sorting\n",
		    whoami);

	nnames = 0;
	for (mi = &modules; mi; mi = mi->next) {
		for (index = 0; index < mi->nname; index++) {
			if (zflag == 0 && (mi->nl[index]).ncall == 0 &&
			    (mi->nl[index]).time == 0) {
				continue;
			}

			/*
			 * Do not print certain special symbols, like
			 * PRF_EXTSYM, etc. even if zflag was on.
			 */
			if (is_special_sym(&(mi->nl[index])))
				continue;

			namesortnlp[nnames++] = &(mi->nl[index]);
		}
	}

	qsort(namesortnlp, nnames, sizeof (nltype *), namecmp);

	for (index = 1, todo = nnames; index <= ncycle; index++)
		namesortnlp[todo++] = &cyclenl[index];

	(void) printf("\f\nIndex by function name\n\n");

	if (!Cflag)
		index = (todo + 2) / 3;
	else
		index = todo;

	for (i = 0; i < index; i++) {
		if (!Cflag) {
			for (j = i; j < todo; j += index) {
				nlp = namesortnlp[j];

				if (nlp->printflag) {
					(void) sprintf(peterbuffer,
					    "[%d]", nlp->index);
				} else {
					(void) sprintf(peterbuffer,
					    "(%d)", nlp->index);
				}

				if (j < nnames) {
					if (does_clash(namesortnlp,
					    j, nnames)) {
						(void) printf(
						    "%6.6s %*d:%-*.*s",
						    peterbuffer,
						    IDFMT(nlp->module->id),
						    nlp->module->id,
						    NMFMT(nlp->module->id),
						    NMFMT(nlp->module->id),
						    nlp->name);
					} else {
					(void) printf("%6.6s %-19.19s",
					    peterbuffer, nlp->name);
					}
				} else {
					(void) printf("%6.6s ", peterbuffer);
					(void) sprintf(peterbuffer,
					    "<cycle %d>", nlp->cycleno);
					(void) printf("%-19.19s", peterbuffer);
				}
			}
		} else {
			nlp = namesortnlp[i];

			if (nlp->printflag)
				(void) sprintf(peterbuffer, "[%d]", nlp->index);
			else
				(void) sprintf(peterbuffer, "(%d)", nlp->index);

			if (i < nnames) {
				const char *d = demangled_name(nlp);

				if (does_clash(namesortnlp, i, nnames)) {
					(void) printf("%6.6s %d:%s\n",
					    peterbuffer, nlp->module->id, d);
				} else {
					(void) printf("%6.6s %s\n", peterbuffer,
					    d);
				}

				if (d != nlp->name) {
					(void) printf("%6.6s   [%s]", "",
					    nlp->name);
					free((void *)d);
				}
			} else {
				(void) printf("%6.6s ", peterbuffer);
				(void) sprintf(peterbuffer, "<cycle %d>",
				    nlp->cycleno);
				(void) printf("%-33.33s", peterbuffer);
			}
		}
		(void) printf("\n");
	}
	free(namesortnlp);
}
