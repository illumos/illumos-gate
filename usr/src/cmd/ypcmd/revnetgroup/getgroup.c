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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SMI4.1 1.5 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "table.h"
#include "util.h"
#include "getgroup.h"

#define	MAXGROUPLEN 1024

/*
 * Stolen mostly, from getnetgrent.c
 *
 * my_getgroup() performs the same function as _getgroup(), but operates
 * on /etc/netgroup directly, rather than doing yp lookups.
 *
 * /etc/netgroup must first loaded into a hash table so the matching
 * function can look up lines quickly.
 */


/* To check for cycles in netgroups */
struct list {
	char *name;
	struct list *nxt;
};


extern stringtable ngtable; /* stored info from /etc/netgroup */

static struct grouplist *grouplist; /* stores a list of users in a group */

static char *any();
static char *match();
static char *fill();
static void freegrouplist();
static void doit();



static void
freegrouplist()
{
	struct grouplist *gl;

	for (gl = grouplist; gl != NULL; gl = gl->gl_nxt) {
		FREE(gl->gl_name);
		FREE(gl->gl_domain);
		FREE(gl->gl_machine);
		FREE(gl);
	}
	grouplist = NULL;
}




struct grouplist *
my_getgroup(group)
	char *group;
{
	freegrouplist();
	doit(group, (struct list *) NULL);
	return (grouplist);
}





/*
 * recursive function to find the members of netgroup "group". "list" is
 * the path followed through the netgroups so far, to check for cycles.
 */
static void
doit(group, list)
	char *group;
	struct list *list;
{
	register char *p, *q;
	register struct list *ls;
	struct list tmplist;
	char *val;
	struct grouplist *gpls;


	/*
	 * check for non-existing groups
	 */
	if ((val = match(group)) == NULL) {
		return;
	}


	/*
	 * check for cycles
	 */
	for (ls = list; ls != NULL; ls = ls->nxt) {
		if (strcmp(ls->name, group) == 0) {
			(void) fprintf(stderr,
				"Cycle detected in /etc/netgroup: %s.\n",
				group);
			return;
		}
	}


	ls = &tmplist;
	ls->name = group;
	ls->nxt = list;
	list = ls;

	p = val;
	while (p != NULL) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == EOS || *p == '#')
			break;
		if (*p == '(') {
			gpls = MALLOC(struct grouplist);
			p++;

			if (!(p = fill(p, &gpls->gl_machine, ',')))  {
				goto syntax_error;
			}
			if (!(p = fill(p, &gpls->gl_name, ','))) {
				goto syntax_error;
			}
			if (!(p = fill(p, &gpls->gl_domain, ')'))) {
				goto syntax_error;
			}
			gpls->gl_nxt = grouplist;
			grouplist = gpls;
		} else {
			q = any(p, " \t\n#");
			if (q && *q == '#')
				break;
			*q = EOS;
			doit(p, list);
			*q = ' ';
		}
		p = any(p, " \t");
	}
	return;

syntax_error:
	(void) fprintf(stderr, "syntax error in /etc/netgroup\n");
	(void) fprintf(stderr, "--- %s %s\n", group, val);
}




/*
 * Fill a buffer "target" selectively from buffer "start".
 * "termchar" terminates the information in start, and preceding
 * or trailing white space is ignored.  If the buffer "start" is
 * empty, "target" is filled with "*". The location just after the
 * terminating character is returned.
 */
static char *
fill(start, target, termchar)
	char *start;
	char **target;
	char termchar;
{
	register char *p;
	register char *q;
	register char *r;
	int size;

	for (p = start; *p == ' ' || *p == '\t'; p++)
		;
	r = strchr(p, termchar);
	if (r == (char *)NULL) {
		return ((char *)NULL);
	}
	if (p == r) {
		*target = NULL;
	} else {
		for (q = r-1; *q == ' ' || *q == '\t'; q--)
			;
		size = q-p+1;
		STRNCPY(*target, p, size);
	}
	return (r+1);
}


/*
 * scans cp, looking for a match with any character
 * in match.  Returns pointer to place in cp that matched
 * (or NULL if no match)
 */
static char *
any(cp, match)
	register char *cp;
	char *match;
{
	register char *mp, c;

	while (c = *cp) {
		for (mp = match; *mp; mp++)
			if (*mp == c)
				return (cp);
		cp++;
	}
	return (NULL);
}



/*
 * The equivalent of yp_match. Returns the match, or NULL if there is none.
 */
static char *
match(group)
	char *group;
{
	return (lookup(ngtable, group));
}
