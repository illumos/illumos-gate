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
 * ns_fnreaddir.c
 *
 * Copyright (c) 1995 - 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <xfn/xfn.h>
#include "automount.h"
#include "ns_fnutils.h"


/*
 * Given the name of an XFN map, create a list of the map entries for a
 * given user.  Set error to zero on success.
 *
 *	extern void
 *	getmapkeys_fn(const char *map, struct dir_entry **, int *error,
 *	    int *cache_time, uid_t);
 */

/*
 * Given a multi-component composite name, construct the corresponding
 * context handle and the context handle of its prefix.  The prefix is
 * that part of the name up to (and possibly including) the last slash
 * in the name.  Return zero on success.
 *
 * eg:	user/jane/service  =>  user/jane + service
 *	org/ssi.eng/user   =>  org/ssi.eng/ + user
 */
static int
get_contexts(const FN_composite_name_t *, FN_ctx_t **ctxp,
    FN_ctx_t **prefix_ctxp, FN_ctx_t *init_ctx, FN_status_t *);

/*
 * Split a multi-component composite name into its last component and
 * its other components.  Return zero on success.
 */
static int
split_cname(const FN_composite_name_t *name, FN_composite_name_t **last,
    FN_composite_name_t **lead);

/*
 * Given a context and its prefix context (defined above), determine
 * whether the context, its NNS context, or both should be listed.
 * (The syntaxes of the contexts are used to help make this
 * determination.)  Add the subdirectories of the appropriate
 * context(s) to the dir_entry list.  Return zero on success.
 *
 * eg:	"ls /xfn/user		=>  list context only
 *	"ls /xfn/org/ssi.eng"	=>  list NNS only
 *	"ls /xfn/.../c=us"	=>  list context and NNS
 */
static int
list_ctx_and_or_nns(FN_ctx_t *ctx, FN_ctx_t *prefix_ctx, struct dir_entry **,
    FN_status_t *);

/*
 * Given a context and its prefix context (defined above), return true
 * if the NNS of the context should be listed but the context itself
 * should not.
 */
static bool_t
need_nns_only(FN_ctx_t *ctx, FN_ctx_t *prefix_ctx, FN_status_t *);

/*
 * Return true if both the given context and its NNS should be listed.
 */
static bool_t
need_ctx_and_nns(FN_ctx_t *, FN_status_t *);

/*
 * Add the subdirectories of a context to the dir_entry list.  Return
 * zero on success.
 */
static int
list_ctx(FN_ctx_t *, struct dir_entry **, FN_status_t *);

/*
 * Given a context and its name relative to the root of its rightmost
 * naming system, add the context's subdirectories to the dir_entry
 * list.  If syntax is non-NULL recursively list names until a context
 * with a different syntax is encountered, otherwise list one level
 * only.  May modify "name".  Return zero on success.
 *
 * eg:  For the context org/eng with syntax "dot-separated, right-to-left",
 * the compound name "eng" would be passed in, and the following might
 * be added to the dir_entry list:
 * 	ssi.eng
 *	feds.ssi.eng
 * 	ste.eng
 */
static int
list_ctx_aux(FN_ctx_t *, FN_compound_name_t *name, const FN_attrset_t *syntax,
    struct dir_entry **, FN_status_t *);

/*
 * Add a name to a dir_entry list.  Return zero on success.
 */
static int
add_name_to_dirlist(const FN_compound_name_t *, struct dir_entry **);

/*
 * Return true if a set of syntax attributes correspond to a
 * hierarchical namespace with a slash separator.  Return false on
 * error.
 */
static bool_t
slash_hierarchy(const FN_attrset_t *syntax);

/*
 * Return true if a set of syntax attributes correspond to a
 * hierarchical namespace with a separator other than a slash.
 * Return false on error.
 */
static bool_t
non_slash_hierarchy(const FN_attrset_t *syntax);

/*
 * Return true if two syntax attribute sets are equal.
 */
static bool_t
syntax_attrs_equal(const FN_attrset_t *, const FN_attrset_t *);

/*
 * Return a value of a given attribute in an attribute set, or NULL
 * on error.
 */
static const FN_attrvalue_t *
get_attrval(const FN_attrset_t *, const FN_identifier_t *attr_id);

/*
 * Lookup a name and return the corresponding context handle.  On
 * error return NULL and, if "log" is true or the error is transient,
 * log an error message.
 */
static FN_ctx_t *
lookup_ctx(FN_ctx_t *, const FN_composite_name_t *, bool_t log, FN_status_t *);


/*
 * Unlike during a lookup or mount, transient errors are tolerated.  A
 * potentially transient error during a readdir() (such as no response
 * from an X.500 server) could result in an incomplete listing, but at
 * least readdir() will return everything that it can.  Note that it
 * is still possible to mount a directory that for some reason did not
 * show up in a prior readdir().
 */
void
getmapkeys_fn(const char *map, struct dir_entry **entries_p, int *error,
    int *cache_time, uid_t uid)
{
	FN_composite_name_t	*name;
	FN_status_t		*status;
	FN_ctx_t		*init_ctx;
	FN_ctx_t		*ctx;
	FN_ctx_t		*prefix_ctx;
	struct dir_entry	*p;

	*cache_time = RDDIR_CACHE_TIME;

	if ((init_fn() != 0) || (status = fn_status_create()) == NULL) {
		log_mem_failure();
		*error = -1;
		return;
	}
	init_ctx = _fn_ctx_handle_from_initial_with_uid(uid, 0, status);
	if (init_ctx == NULL) {
		logstat(status, "", "No initial context");
		fn_status_destroy(status);
		return;
	}

	if (strcmp(map, FNPREFIX) == 0) {
		/*
		 * List the initial context.
		 * Contents of initial ctx is user-relative
		 */
		*cache_time = 0;
		*error = list_ctx(init_ctx, entries_p, status);
	} else if (strcmp(map, FNPREFIX "/_dns") == 0) {
		/* Cannot list DNS; report success but no entries. */
		*cache_time = 1000000;	/* no sense trying again */
		*error = 0;
	} else {
		if (strcmp(map, FNPREFIX "/...") == 0) {
			/* List X.500 but not DNS. */
			name = new_cname("_x500");
		} else {
			name = new_cname(map + FNPREFIXLEN + 1);
		}
		if (name == NULL) {
			*error = -1;
		} else if (fn_composite_name_count(name) == 1) {

			/* List an atomic name. */
			ctx = lookup_ctx(init_ctx, name, TRUE, status);
			if (ctx != NULL) {
				*error = list_ctx_and_or_nns(ctx, init_ctx,
				    entries_p, status);
				fn_ctx_handle_destroy(ctx);
			} else {
				*error = -1;
			}
		} else {

			/* List a multi-component name. */
			*error = get_contexts(name, &ctx, &prefix_ctx,
			    init_ctx, status);
			if (*error == 0) {
				*error = list_ctx_and_or_nns(ctx, prefix_ctx,
				    entries_p, status);
				fn_ctx_handle_destroy(ctx);
				fn_ctx_handle_destroy(prefix_ctx);
			}
		}
		fn_composite_name_destroy(name);
	}
	fn_status_destroy(status);
	fn_ctx_handle_destroy(init_ctx);

	if (*error == 0) {
		/*
		 * create the binary tree of entries
		 */
		for (p = *entries_p; p != NULL; p = p->next)
			btree_enter(entries_p, p);
	}
}


static int
get_contexts(const FN_composite_name_t *name, FN_ctx_t **ctxp,
    FN_ctx_t **prefix_ctxp, FN_ctx_t *init_ctx, FN_status_t *status)
{
	FN_composite_name_t	*prefix = NULL;
	FN_composite_name_t	*suffix = NULL;
	FN_ctx_t		*nns_ctx;

	/*
	 * Break a name such as "pre/fix/suffix" into "pre/fix/" and
	 * "suffix".  If that fails, try "pre/fix" and "suffix".  This
	 * can be more efficient than doing it the reverse order.
	 */
	if (split_cname(name, &suffix, &prefix) != 0) {
		return (-1);
	}
	*ctxp = NULL;
	*prefix_ctxp = lookup_ctx(init_ctx, prefix, TRUE, status);
	fn_composite_name_destroy(prefix);

	if (*prefix_ctxp != NULL) {
		nns_ctx = lookup_ctx(*prefix_ctxp, slash_cname, FALSE, status);
		if (nns_ctx != NULL) {
			*ctxp = lookup_ctx(nns_ctx, suffix, FALSE, status);
			if (*ctxp != NULL) {
				fn_ctx_handle_destroy(*prefix_ctxp);
				*prefix_ctxp = nns_ctx;
			} else {
				fn_ctx_handle_destroy(nns_ctx);
			}
		}
		if (*ctxp == NULL) {
			*ctxp =
			    lookup_ctx(*prefix_ctxp, suffix, FALSE, status);
		}
	}
	fn_composite_name_destroy(suffix);
	return (*ctxp != NULL ? 0 : -1);
}


static int
split_cname(const FN_composite_name_t *name, FN_composite_name_t **last,
    FN_composite_name_t **lead)
{
	void	*iter;

	(void) fn_composite_name_last(name, &iter);
	*last = fn_composite_name_suffix(name, iter);
	*lead = fn_composite_name_prefix(name, iter);
	if (*last == NULL || *lead == NULL) {
		log_mem_failure();
		fn_composite_name_destroy(*last);
		fn_composite_name_destroy(*lead);
		return (-1);
	}
	return (0);
}


static int
list_ctx_and_or_nns(FN_ctx_t *ctx, FN_ctx_t *prefix_ctx,
    struct dir_entry **entries_p, FN_status_t *status)
{
	FN_ctx_t	*nns_ctx;
	int		rc;

	if (!need_nns_only(ctx, prefix_ctx, status)) {
		if (list_ctx(ctx, entries_p, status) != 0) {
			return (-1);
		}
		if (!need_ctx_and_nns(ctx, status)) {
			return (0);
		}
	}
	nns_ctx = lookup_ctx(ctx, slash_cname, FALSE, status);
	if (nns_ctx == NULL) {
		return (0);
	}
	rc = list_ctx(nns_ctx, entries_p, status);
	fn_ctx_handle_destroy(nns_ctx);
	return (rc);
}


/*
 * True if ctx has a hierarchical syntax with a non-slash separator
 * and prefix_ctx either has the same syntax or does not provide any
 * syntax ("..." should be the only example of the latter condition).
 */
static bool_t
need_nns_only(FN_ctx_t *ctx, FN_ctx_t *prefix_ctx, FN_status_t *status)
{
	FN_attrset_t	*syn;
	FN_attrset_t	*prefix_syn;
	bool_t		retval;

	syn = fn_ctx_get_syntax_attrs(ctx, empty_cname, status);
	if (syn == NULL || !non_slash_hierarchy(syn)) {
		fn_attrset_destroy(syn);
		return (FALSE);
	}
	/*
	 * ctx is hierarchical and not slash-separated.  How about prefix_ctx?
	 */
	prefix_syn = fn_ctx_get_syntax_attrs(prefix_ctx, empty_cname, status);
	retval = (prefix_syn == NULL) || syntax_attrs_equal(syn, prefix_syn);

	fn_attrset_destroy(syn);
	fn_attrset_destroy(prefix_syn);
	return (retval);
}


/*
 * True if ctx has a slash-separated hierarchical syntax.
 */
static bool_t
need_ctx_and_nns(FN_ctx_t *ctx, FN_status_t *status)
{
	FN_attrset_t	*syn;
	bool_t		retval;

	syn = fn_ctx_get_syntax_attrs(ctx, empty_cname, status);
	if (syn == NULL) {
		return (FALSE);
	}
	retval = slash_hierarchy(syn);
	fn_attrset_destroy(syn);
	return (retval);
}


static int
list_ctx(FN_ctx_t *ctx, struct dir_entry **entries_p, FN_status_t *status)
{
	FN_attrset_t		*syntax;
	FN_compound_name_t	*name;
	int			retval;

	syntax = fn_ctx_get_syntax_attrs(ctx, empty_cname, status);
	if (syntax == NULL) {
		logstat(status, "", "bad syntax attributes");
		return (-1);
	}
	name =
	    fn_compound_name_from_syntax_attrs(syntax, empty_string, status);
	if (name == NULL) {
		logstat(status, "", "could not create compound name");
		fn_attrset_destroy(syntax);
		return (-1);
	}
	if (!non_slash_hierarchy(syntax)) {
		fn_attrset_destroy(syntax);
		syntax = NULL;
	}
	retval = list_ctx_aux(ctx, name, syntax, entries_p, status);
	fn_attrset_destroy(syntax);
	fn_compound_name_destroy(name);
	return (retval);
}


static int
list_ctx_aux(FN_ctx_t *ctx, FN_compound_name_t *name,
    const FN_attrset_t *syntax, struct dir_entry **entries_p,
    FN_status_t *status)
{
	FN_bindinglist_t	*bindings;
	FN_string_t		*child;
	FN_ref_t		*ref;
	unsigned int		stat;
	int			rc = 0;
	void			*iter;

	bindings = fn_ctx_list_bindings(ctx, empty_cname, status);
	if (bindings == NULL) {
		return (0);
	}
	while ((child = fn_bindinglist_next(bindings, &ref, status)) != NULL) {
		if (fn_compound_name_append_comp(name, child, &stat) == 0) {
			rc = -1;
			break;
		}
		if (add_name_to_dirlist(name, entries_p) != 0) {
			rc = -1;
			break;
		}
		if (syntax != NULL) {
			/* Traverse hierarchy. */
			ctx = fn_ctx_handle_from_ref(ref, XFN2(0) status);
			if (ctx != NULL) {
				rc = list_ctx_aux(ctx, name, syntax, entries_p,
				    status);
				fn_ctx_handle_destroy(ctx);
				if (rc != 0) {
					break;
				}
			}
		}
		fn_ref_destroy(ref);
		fn_string_destroy(child);
		(void) fn_compound_name_last(name, &iter);
		(void) fn_compound_name_next(name, &iter);
		(void) fn_compound_name_delete_comp(name, &iter);
	}
	fn_string_destroy(child);
	fn_bindinglist_destroy(bindings XFN1(status));
	return (rc);
}


static int
add_name_to_dirlist(const FN_compound_name_t *name,
    struct dir_entry **entries_p)
{
	FN_string_t		*string;
	char			*str;
	unsigned int		stat;
	struct dir_entry	*entry;

	string = fn_string_from_compound_name(name);
	if (string == NULL) {
		log_mem_failure();
		return (-1);
	}
	str = (char *)fn_string_str(string, &stat);
	if (str != NULL) {
		str = auto_rddir_strdup(str);
	}
	fn_string_destroy(string);
	if (str == NULL) {
		log_mem_failure();
		return (-1);
	}

	/* LINTED pointer alignment */
	entry = (struct dir_entry *)
		auto_rddir_malloc(sizeof (*entry));
	if (entry == NULL) {
		log_mem_failure();
		free(str);
		return (-1);
	}
	(void) memset((char *)entry, 0, sizeof (*entry));
	entry->name = str;
	entry->next = *entries_p;
	*entries_p = entry;
	return (0);
}


/*
 * Identifiers of syntax attributes for direction and separator.
 */

static const FN_identifier_t syntax_direction = {
	FN_ID_STRING,
	sizeof ("fn_std_syntax_direction") - 1,
	"fn_std_syntax_direction"
};

static const FN_identifier_t syntax_separator = {
	FN_ID_STRING,
	sizeof ("fn_std_syntax_separator") - 1,
	"fn_std_syntax_separator"
};


static bool_t
slash_hierarchy(const FN_attrset_t *syntax)
{
	const FN_attrvalue_t	*dir = get_attrval(syntax, &syntax_direction);
	const FN_attrvalue_t	*sep = get_attrval(syntax, &syntax_separator);

	return (dir != NULL &&
	    memcmp("flat", dir->contents, dir->length) != 0 &&
	    sep != NULL &&
	    memcmp("/", sep->contents, sep->length) == 0);
}


static bool_t
non_slash_hierarchy(const FN_attrset_t *syntax)
{
	const FN_attrvalue_t	*dir = get_attrval(syntax, &syntax_direction);
	const FN_attrvalue_t	*sep = get_attrval(syntax, &syntax_separator);

	return (dir != NULL &&
	    memcmp("flat", dir->contents, dir->length) != 0 &&
	    sep != NULL &&
	    memcmp("/", sep->contents, sep->length) != 0);
}


static bool_t
syntax_attrs_equal(const FN_attrset_t *syn1, const FN_attrset_t *syn2)
{
	const FN_attribute_t	*attr;
	const FN_attrvalue_t	*val1;
	const FN_attrvalue_t	*val2;
	void			*iter1;
	void			*iter2;

	if (fn_attrset_count(syn1) != fn_attrset_count(syn2)) {
		return (FALSE);
	}
	for (attr = fn_attrset_first(syn1, &iter1);
	    attr != NULL;
	    attr = fn_attrset_next(syn1, &iter1)) {
		val1 = fn_attribute_first(attr, &iter2);
		val2 = get_attrval(syn2, fn_attribute_identifier(attr));
		if ((val1 == NULL && val2 != NULL) ||
		    (val1 != NULL && val2 == NULL)) {
			return (FALSE);
		}
		if (val1 != NULL && val2 != NULL) {
			if (val1->length != val2->length ||
			    memcmp(val1->contents, val2->contents,
				    val1->length) != 0) {
				return (FALSE);
			}
		}
	}
	return (TRUE);
}


static const FN_attrvalue_t *
get_attrval(const FN_attrset_t *attrs, const FN_identifier_t *attr_id)
{
	const FN_attribute_t	*attr;
	void			*iter;

	attr = fn_attrset_get(attrs, attr_id);
	if (attr != NULL) {
		return (fn_attribute_first(attr, &iter));
	} else {
		return (NULL);
	}
}


static FN_ctx_t *
lookup_ctx(FN_ctx_t *ctx, const FN_composite_name_t *name, bool_t log,
    FN_status_t *status)
{
	FN_ref_t	*ref;
	char		*msg;

	ref = fn_ctx_lookup(ctx, name, status);
	if (ref == NULL) {
		ctx = NULL;
		msg = "lookup failed";
	} else {
		ctx = fn_ctx_handle_from_ref(ref, XFN2(0) status);
		fn_ref_destroy(ref);
		if (ctx == NULL) {
			msg = "could not construct context handle";
		}
	}
	if (ctx == NULL && verbose && (log || transient(status))) {
		logstat(status, "", msg);
	}
	return (ctx);
}
