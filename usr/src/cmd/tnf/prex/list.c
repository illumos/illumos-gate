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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libintl.h>
#include <search.h>

#include "source.h"
#include "queue.h"
#include "list.h"
#include "spec.h"
#include "new.h"
#include "fcn.h"

extern caddr_t  g_commitfunc;


/*
 * Typedefs
 */

typedef struct list_probe_args {
	spec_t		 *speclist_p;
	expr_t		 *exprlist_p;
} list_probe_args_t;

typedef struct list_attrs_args {
	spec_t		 *speclist_p;
	void		   *attrroot_p;
} list_attrs_args_t;

typedef struct attr_node {
	char		   *name;
	void		   *valsroot_p;
} attr_node_t;

typedef struct vals_node {
	char		   *name;
} vals_node_t;


/*
 * Globals
 */


/*
 * Declarations
 */

static tnfctl_errcode_t listprobe(tnfctl_handle_t *hndl,
	tnfctl_probe_t *ref_p, void *calldata_p);
static tnfctl_errcode_t probescan(tnfctl_handle_t *hndl,
	tnfctl_probe_t *ref_p, void *calldata_p);
static void printattrval(spec_t * spec_p, char *attr, char *value,
	void *pdata);
static void attrscan(spec_t * spec_p, char *attr, char *values, void *pdata);
static int attrcompare(const void *node1, const void *node2);
static int valscompare(const void *node1, const void *node2);
static void printattrs(const void *node, VISIT order, int level);
static void printvals(const void *node, VISIT order, int level);

#if 0
static void	 attrnodedel(attr_node_t * an_p);
#endif

static void valadd(spec_t * spec_p, char *val, void *calldata_p);


/* ---------------------------------------------------------------- */
/* ----------------------- Public Functions ----------------------- */
/* ---------------------------------------------------------------- */

extern tnfctl_handle_t	*g_hndl;

/*
 * list_set() - lists all of the current probes in a target process
 */

void
list_set(spec_t * speclist_p, char *setname_p)
{
	set_t *set_p;
	list_probe_args_t args;
	tnfctl_errcode_t err;

	set_p = set_find(setname_p);
	if (!set_p) {
		semantic_err(gettext("missing or invalid set"));
		return;
	}
	args.speclist_p = speclist_p;
	args.exprlist_p = set_p->exprlist_p;
	err = tnfctl_probe_apply(g_hndl, listprobe, &args);
	if (err) {
		semantic_err(gettext("listing error : %s"),
				tnfctl_strerror(err));
	}
}


/*
 * list_expr() - lists all of the current probes in an expression list
 */

void
list_expr(spec_t * speclist_p, expr_t * expr_p)
{
	list_probe_args_t args;
	tnfctl_errcode_t err;

	args.speclist_p = speclist_p;
	args.exprlist_p = expr_p;
	err = tnfctl_probe_apply(g_hndl, listprobe, &args);
	if (err) {
		semantic_err(gettext("listing error : %s"),
				tnfctl_strerror(err));
	}
}


/*
 * list_values() - list all the values for a supplied spec
 */

void
list_values(spec_t * speclist_p)
{
	list_attrs_args_t args;
	tnfctl_errcode_t err;

	/* setup argument block */
	args.speclist_p = speclist_p;
	args.attrroot_p = NULL;

	/* traverse the probes, recording attributes that match */
	err = tnfctl_probe_apply(g_hndl, probescan, &args);
	if (err) {
		semantic_err(gettext("probe traversal error : %s"),
				tnfctl_strerror(err));
	}

	/* pretty print the results */
	twalk(args.attrroot_p, printattrs);

	/* destroy the attribute tree */
	while (args.attrroot_p) {
		attr_node_t   **aptr;
		char			*anameptr;

		aptr = (attr_node_t **) args.attrroot_p;

		/* destroy the value tree */
		while ((*aptr)->valsroot_p) {
			vals_node_t   **vptr;
			char			*vnameptr;

			vptr = (vals_node_t **) (*aptr)->valsroot_p;
			vnameptr = (*vptr)->name;
#ifdef LEAKCHK
			(void) fprintf(stderr, "freeing value \"%s\"\n",
				vnameptr);
#endif
			(void) tdelete((void *) *vptr, &(*aptr)->valsroot_p,
				valscompare);
			if (vnameptr) free(vnameptr);
		}

		anameptr = (*aptr)->name;
#ifdef LEAKCHK
		(void) fprintf(stderr, "freeing attr \"%s\"\n", anameptr);
#endif
		(void) tdelete((void *) *aptr, &args.attrroot_p, attrcompare);
		if (anameptr) free(anameptr);
	}

}				/* end list_values */


/*
 * list_getattrs() - build an attribute string for this probe.
 */


#define	BUF_LIMIT	2048

char *
list_getattrs(tnfctl_probe_t *probe_p)
{
	tnfctl_errcode_t	err;
	tnfctl_probe_state_t	p_state;
	char			*attrs;
	char			buffer[BUF_LIMIT];
	char			*buf_p;
	char			*buf_end;
	int			str_len;
	size_t			len;

	err = tnfctl_probe_state_get(g_hndl, probe_p, &p_state);
	if (err) {
		attrs = malloc(2);
		if (attrs)
			attrs[0] = '\0';
		return (attrs);
	}

	buf_p = buffer;
	buf_end = buf_p + BUF_LIMIT;
	str_len = sprintf(buf_p, "enable %s; trace %s; ",
				(p_state.enabled) ? "on" : "off",
				(p_state.traced) ? "on" : "off");
	buf_p += str_len;
	if (p_state.obj_name) {
		str_len = strlen(p_state.obj_name);
		if (buf_p + str_len < buf_end) {
			str_len = sprintf(buf_p, "object %s; ",
							p_state.obj_name);
			buf_p += str_len;
		}
	}
	str_len = sprintf(buf_p, "funcs");
	buf_p += str_len;

	/* REMIND: add limit for string size */
	if (p_state.func_names) {
		int 	i = 0;
		char	*fcnname;

		while (p_state.func_names[i]) {
			(void) strcat(buffer, " ");

			fcnname = fcn_findname(p_state.func_names[i]);
			if (fcnname) {
				(void) strcat(buffer, "&");
				(void) strcat(buffer, fcnname);
			} else
				(void) strcat(buffer, p_state.func_names[i]);
			i++;
		}
	}

	(void) strcat(buffer, ";");

	len = strlen(buffer) + strlen(p_state.attr_string) + 1;
	attrs = (char *) malloc(len);

	if (attrs) {
		(void) strcpy(attrs, buffer);
		(void) strcat(attrs, p_state.attr_string);
	}

	return (attrs);
}


/* ---------------------------------------------------------------- */
/* ----------------------- Private Functions ---------------------- */
/* ---------------------------------------------------------------- */

/*
 * probescan() - function used as a callback, gathers probe attributes and
 * values
 */
/*ARGSUSED*/
static tnfctl_errcode_t
probescan(tnfctl_handle_t *hndl, tnfctl_probe_t *ref_p, void *calldata_p)
{
	list_attrs_args_t *args_p = (list_attrs_args_t *) calldata_p;
	spec_t		*speclist_p;
	spec_t		*spec_p;
	char		*attrs;

	speclist_p = args_p->speclist_p;
	spec_p = NULL;

	attrs = list_getattrs(ref_p);

	while (spec_p = (spec_t *) queue_next(&speclist_p->qn, &spec_p->qn)) {
		spec_attrtrav(spec_p, attrs, attrscan, calldata_p);
	}

	if (attrs)
		free(attrs);

	return (TNFCTL_ERR_NONE);
}


/*
 * attrscan() - called on each matching attr/values component
 */

/*ARGSUSED*/
static void
attrscan(spec_t * spec_p,
	char *attr,
	char *values,
	void *pdata)
{
	list_attrs_args_t *args_p = (list_attrs_args_t *) pdata;
	attr_node_t	*an_p;
	attr_node_t   **ret_pp;
	static spec_t  *allspec = NULL;

	if (!allspec)
		allspec = spec(".*", SPEC_REGEXP);

	an_p = new(attr_node_t);

#ifdef LEAKCHK
	(void) fprintf(stderr, "creating attr \"%s\"\n", attr);
#endif
	an_p->name = strdup(attr);
	an_p->valsroot_p = NULL;

	ret_pp = tfind((void *) an_p, &args_p->attrroot_p, attrcompare);

	if (ret_pp) {
		/*
		 * we already had a node for this attribute; delete ours *
		 * and point at the original instead.
		 */
#ifdef LEAKCHK
		(void) fprintf(stderr, "attr already there \"%s\"\n", attr);
#endif
		if (an_p->name)
			free(an_p->name);
		free(an_p);

		an_p = *ret_pp;
	} else {
		(void) tsearch((void *) an_p, &args_p->attrroot_p, attrcompare);
	}

	spec_valtrav(allspec, values, valadd, (void *) an_p);

}				/* end attrscan */


/*
 * valadd() - add vals to an attributes tree
 */

/*ARGSUSED*/
static void
valadd(spec_t * spec_p,
	char *val,
	void *calldata_p)
{
	attr_node_t	*an_p = (attr_node_t *) calldata_p;

	vals_node_t	*vn_p;
	vals_node_t   **ret_pp;

	vn_p = new(vals_node_t);
#ifdef LEAKCHK
	(void) fprintf(stderr, "creating value \"%s\"\n", val);
#endif
	vn_p->name = strdup(val);

	ret_pp = tfind((void *) vn_p, &an_p->valsroot_p, valscompare);

	if (ret_pp) {
		/* we already had a node for this value */
#ifdef LEAKCHK
		(void) fprintf(stderr, "value already there \"%s\"\n", val);
#endif
		if (vn_p->name)
			free(vn_p->name);
		free(vn_p);
	} else {
		(void) tsearch((void *) vn_p, &an_p->valsroot_p, valscompare);
	}


}				/* end valadd */


/*
 * attrcompare() - compares attribute nodes, alphabetically
 */

static int
attrcompare(const void *node1,
		const void *node2)
{
	return strcmp(((attr_node_t *) node1)->name,
		((attr_node_t *) node2)->name);

}				/* end attrcompare */


/*
 * valscompare() - compares attribute nodes, alphabetically
 */

static int
valscompare(const void *node1,
		const void *node2)
{
	return strcmp(((vals_node_t *) node1)->name,
		((vals_node_t *) node2)->name);

}				/* end valscompare */


/*
 * printattrs() - prints attributes from the attr tree
 */

/*ARGSUSED*/
static void
printattrs(const void *node,
	VISIT order,
	int level)
{
	attr_node_t	*an_p = (*(attr_node_t **) node);

	if (order == postorder || order == leaf) {
		(void) printf("%s =\n", an_p->name);
		twalk(an_p->valsroot_p, printvals);
	}
}				/* end printattrs */


/*
 * printvals() - prints values from a value tree
 */

/*ARGSUSED*/
static void
printvals(const void *node,
	VISIT order,
	int level)
{
	vals_node_t	*vn_p = (*(vals_node_t **) node);

	if (order == postorder || order == leaf)
		(void) printf("	   %s\n", vn_p->name);

}				/* end printvals */


#if 0
/*
 * attrnodedel() - deletes an attr_node_t after the action
 */

static void
attrnodedel(attr_node_t * an_p)
{
	if (an_p->name)
		free(an_p->name);

	/* destroy the value tree */
	while (an_p->valsroot_p) {
		vals_node_t   **ptr;

		ptr = (vals_node_t **) an_p->valsroot_p;
		(void) tdelete((void *) *ptr, &an_p->valsroot_p, valscompare);
	}

	/* We don't need to free this object, since tdelete() appears to */
	/* free(an_p); */

}				/* end attrnodedel */
#endif


/*
 * listprobe() - function used as a callback, pretty prints a probe
 */
/*ARGSUSED*/
static tnfctl_errcode_t
listprobe(tnfctl_handle_t *hndl, tnfctl_probe_t *ref_p, void *calldata_p)
{
	static spec_t	*default_speclist = NULL;
	list_probe_args_t *args_p = (list_probe_args_t *) calldata_p;
	spec_t		*speclist_p;
	spec_t		*spec_p;
	boolean_t	sawattr;
	char		*attrs;

	/* build a default speclist if there is not one built already */
	if (!default_speclist) {
		default_speclist = spec_list(
			spec_list(
				spec_list(
					spec_list(
						spec_list(
							spec("name",
								SPEC_EXACT),
							spec("enable",
								SPEC_EXACT)),
						spec("trace", SPEC_EXACT)),
					spec("file", SPEC_EXACT)),
				spec("line", SPEC_EXACT)),
			spec("funcs", SPEC_EXACT));
	}
	attrs = list_getattrs(ref_p);

	if (expr_match(args_p->exprlist_p, attrs)) {
		speclist_p = args_p->speclist_p;
		speclist_p = (speclist_p) ? speclist_p : default_speclist;

		spec_p = NULL;
		while (spec_p = (spec_t *)
			queue_next(&speclist_p->qn, &spec_p->qn)) {
			sawattr = B_FALSE;
			spec_attrtrav(spec_p, attrs, printattrval, &sawattr);
			if (!sawattr)
				(void) printf("<no attr> ");
		}
		(void) printf("\n");
	}
	if (attrs)
		free(attrs);

	return (TNFCTL_ERR_NONE);
}


/*ARGSUSED*/
static void
printattrval(spec_t * spec_p,
	char *attr,
	char *value,
	void *pdata)
{
	boolean_t	  *bptr = (boolean_t *) pdata;

	*bptr = B_TRUE;

	(void) printf("%s=%s ", attr, (value && *value) ? value : "<no value>");

}				/* end printattrval */
