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

#define	 __EXTENSIONS__	/* header bug! strtok_r is overly hidden */
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>

#include <libcpc.h>

#include "cpucmds.h"

struct args {
	FILE *fp;
	int colnum;
	int margin;
};

struct evlist {
	char *list;
	int size;
};

#define	MAX_RHS_COLUMN	76
#define	EVENT_MARGIN	17
#define	ATTR_MARGIN	20

/*ARGSUSED*/
static void
list_cap(void *arg, uint_t regno, const char *name)
{
	struct args *args = arg;
	int i;

	if ((args->colnum + strlen(name) + 1) > MAX_RHS_COLUMN) {
		(void) fprintf(args->fp, "\n");
		for (i = 0; i < args->margin; i++)
			(void) fprintf(args->fp, " ");
		args->colnum = args->margin;
	}
	args->colnum += fprintf(args->fp, "%s ", name);
}

static void
list_attr(void *arg, const char *name)
{
	/*
	 * The following attributes are used by the commands but should not be
	 * reported to the user, since they may not be specified directly.
	 */
	if (strncmp(name, "picnum", 7) == 0 ||
	    strncmp(name, "count_sibling_usr", 18) == 0 ||
	    strncmp(name, "count_sibling_sys", 18) == 0)
		return;

	list_cap(arg, 0, name);
}

static void *
emalloc(size_t size)
{
	void *ptr;

	if ((ptr = malloc(size)) == NULL) {
		(void) fprintf(stderr, gettext("no memory available\n"));
		exit(1);
	}

	return (ptr);
}

/*
 * Used by allpics_equal().
 */
/*ARGSUSED*/
static void
cap_walker(void *arg, uint_t regno, const char *name)
{
	struct evlist *list = arg;

	list->size += strlen(name);
	if ((list->list = realloc(list->list, list->size + 1)) == NULL) {
		(void) fprintf(stderr, gettext("no memory available\n"));
		exit(1);
	}

	(void) strcat(list->list, name);
}

/*
 * Returns 1 if all counters on this chip can count all possible events.
 */
static int
allpics_equal(cpc_t *cpc)
{
	int	npics = cpc_npic(cpc);
	int	i;
	struct	evlist **lists;
	int	ret = 1;

	lists = emalloc(npics * sizeof (struct evlist *));

	for (i = 0; i < npics; i++) {
		lists[i] = emalloc(sizeof (struct evlist));
		lists[i]->size = 0;
		lists[i]->list = emalloc(1);
		lists[i]->list[0] = '\0';
		cpc_walk_events_pic(cpc, i, lists[i], cap_walker);
	}

	for (i = 1; i < npics; i++)
		if (lists[i]->size != lists[0]->size ||
		    strncmp(lists[i]->list, lists[0]->list,
		    lists[0]->size) != 0) {
			ret = 0;
			break;
		}

	for (i = 0; i < npics; i++) {
		free(lists[i]->list);
		free(lists[i]);
	}
	free(lists);

	return (ret);
}

int
capabilities(cpc_t *cpc, FILE *fp)
{
	struct args _args, *args = &_args;
	char *text, *tok, *cp;
	const char *ccp;
	int npic = cpc_npic(cpc);
	int i, pics_equal = allpics_equal(cpc);

	args->fp = fp;

	if ((ccp = cpc_cciname(cpc)) == NULL)
		ccp = "No information available";
	(void) fprintf(args->fp, "\t%s: %s\n\n",
	    gettext("CPU performance counter interface"), ccp);

	(void) fprintf(args->fp, gettext("\tevent specification syntax:\n"));

	(void) fprintf(args->fp, "\t[picn=]<eventn>[,attr[n][=<val>]]"
	    "[,[picn=]<eventn>[,attr[n][=<val>]],...]\n");

	(void) fprintf(args->fp, gettext("\n\tGeneric Events:\n"));

	if (pics_equal) {
		args->margin = args->colnum = EVENT_MARGIN;
		(void) fprintf(args->fp, "\n\tevent[0-%d]: ", npic - 1);
		cpc_walk_generic_events_pic(cpc, 0, args, list_cap);
		(void) fprintf(args->fp, "\n");
	} else {
		args->margin = EVENT_MARGIN;
		for (i = 0; i < npic; i++) {
			(void) fprintf(args->fp, "\n\tevent%d: ", i);
			if (i < 10) (void) fprintf(args->fp, " ");
			args->colnum = EVENT_MARGIN;
			cpc_walk_generic_events_pic(cpc, i, args, list_cap);
			(void) fprintf(args->fp, "\n");
		}
	}

	(void) fprintf(args->fp, gettext("\n\tSee generic_events(3CPC) for"
	    " descriptions of these events\n\n"));

	(void) fprintf(args->fp, gettext("\tPlatform Specific Events:\n"));

	if (pics_equal) {
		args->margin = args->colnum = EVENT_MARGIN;
		(void) fprintf(args->fp, "\n\tevent[0-%d]: ", npic - 1);
		cpc_walk_events_pic(cpc, 0, args, list_cap);
		(void) fprintf(args->fp, "\n");
	} else {
		args->margin = EVENT_MARGIN;
		for (i = 0; i < npic; i++) {
			(void) fprintf(args->fp, "\n\tevent%d: ", i);
			if (i < 10) (void) fprintf(args->fp, " ");
			args->colnum = EVENT_MARGIN;
			cpc_walk_events_pic(cpc, i, args, list_cap);
			(void) fprintf(args->fp, "\n");
		}
	}

	(void) fprintf(args->fp, "\n\tattributes: ");
	args->colnum = args->margin = ATTR_MARGIN;
	cpc_walk_attrs(cpc, args, list_attr);
	/*
	 * In addition to the attributes published by the kernel, we allow the
	 * user to specify two additional tokens on all platforms. List them
	 * here.
	 */
	list_cap(args, 0, "nouser");
	list_cap(args, 0, "sys");
	(void) fprintf(args->fp, "\n\n\t");
	args->colnum = 8;

	if ((ccp = cpc_cpuref(cpc)) == NULL)
		ccp = "No information available";
	if ((text = strdup(ccp)) == NULL) {
		(void) fprintf(stderr, gettext("no memory available.\n"));
		exit(1);
	}
	for (cp = strtok_r(text, " ", &tok);
	    cp != NULL; cp = strtok_r(NULL, " ", &tok)) {
		if ((args->colnum + strlen(cp) + 1) > MAX_RHS_COLUMN) {
			(void) fprintf(args->fp, "\n\t");
			args->colnum = 8;
		}
		args->colnum += fprintf(args->fp, "%s ", cp);
	}
	(void) fprintf(args->fp, "\n");
	free(text);

	return (0);
}

/*
 * Returns 1 on SMT processors which do not have full CPC hardware for each
 * logical processor.
 */
int
smt_limited_cpc_hw(cpc_t *cpc)
{
	if (strcmp(cpc_cciname(cpc), "Pentium 4 with HyperThreading") == 0)
		return (1);
	return (0);
}
