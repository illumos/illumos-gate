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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Events, FMRIs and authorities must be declared before they can be used.
 * Routines in this file, driven by the parser, create the data structures
 * associated with the declarations.
 */

#include <assert.h>
#include <string.h>

#include <inj_event.h>
#include <inj_err.h>
#include <inj_lex.h>
#include <inj_list.h>
#include <inj.h>

static inj_hash_t inj_decls[ITEMTYPE_NITEMS];
static int inj_decls_initialized;

static inj_hash_t *
item2hash(inj_itemtype_t item)
{
	int i;

	assert(item >= 0 && item < sizeof (inj_decls) / sizeof (inj_hash_t));

	if (!inj_decls_initialized) {
		for (i = 0; i < sizeof (inj_decls) / sizeof (inj_hash_t); i++)
			inj_strhash_create(&inj_decls[i]);
		inj_decls_initialized = 1;
	}

	return (&inj_decls[item]);
}

inj_decl_t *
inj_decl_lookup(const char *name, inj_itemtype_t type)
{
	inj_hash_t *hash = item2hash(type);
	inj_var_t *v;

	if ((v = inj_strhash_lookup(hash, name)) == NULL)
		return (NULL);

	return (inj_hash_get_cookie(v));
}

void
inj_decl_mem_destroy(inj_declmem_t *dlm)
{
	inj_strfree(dlm->dlm_name);

	if (dlm->dlm_type == MEMTYPE_ENUM)
		inj_strhash_destroy(dlm->dlm_enumvals);
}

inj_declmem_t *
inj_decl_mem_create(const char *name, inj_memtype_t type)
{
	inj_declmem_t *dlm = inj_zalloc(sizeof (inj_declmem_t));

	dlm->dlm_name = name;
	dlm->dlm_type = type;

	return (dlm);
}

/* An embedded event, authority, or FMRI */
inj_declmem_t *
inj_decl_mem_create_defined(const char *name, const char *declnm,
    inj_itemtype_t type)
{
	inj_declmem_t *dlm = inj_zalloc(sizeof (inj_declmem_t));

	dlm->dlm_name = name;
	dlm->dlm_type = inj_item2mem(type);

	if ((dlm->dlm_decl = inj_decl_lookup(declnm, type)) == NULL) {
		yyerror("unknown %s %s", inj_item2str(type), declnm);
		return (NULL);
	}

	return (dlm);
}

inj_declmem_t *
inj_decl_mem_create_enum(const char *name, inj_hash_t *vals)
{
	inj_declmem_t *dlm = inj_zalloc(sizeof (inj_declmem_t));

	dlm->dlm_name = name;
	dlm->dlm_type = MEMTYPE_ENUM;
	dlm->dlm_enumvals = vals;

	return (dlm);
}

/* Turn a previously-declared member into an array */
void
inj_decl_mem_make_array(inj_declmem_t *dlm, uint_t dim)
{
	dlm->dlm_flags |= DECLMEM_F_ARRAY;
	dlm->dlm_arrdim = dim;
}

void
inj_decl_destroy(inj_decl_t *decl)
{
	inj_declmem_t *m, *n;

	inj_strfree(decl->decl_name);
	inj_strhash_destroy(&decl->decl_memhash);

	for (m = inj_list_next(&decl->decl_members); m != NULL; m = n) {
		n = inj_list_next(m);

		inj_decl_mem_destroy(m);
	}

	inj_free(decl, sizeof (inj_declmem_t));
}

inj_decl_t *
inj_decl_create(inj_declmem_t *dlm)
{
	inj_decl_t *decl = inj_zalloc(sizeof (inj_decl_t));

	decl->decl_lineno = yylineno;

	inj_strhash_create(&decl->decl_memhash);

	inj_list_append(&decl->decl_members, dlm);
	(void) inj_strhash_insert(&decl->decl_memhash, dlm->dlm_name,
	    (uintptr_t)dlm);

	return (decl);
}

void
inj_decl_addmem(inj_decl_t *decl, inj_declmem_t *dlm)
{
	inj_var_t *v;

	if ((v = inj_strhash_lookup(&decl->decl_memhash, dlm->dlm_name)) !=
	    NULL) {
		inj_decl_t *other = inj_hash_get_cookie(v);

		yyerror("duplicate member name %s (other on line %d)\n",
		    dlm->dlm_name, other->decl_lineno);
		inj_decl_destroy(decl);
		return;
	}

	inj_list_append(&decl->decl_members, dlm);
	(void) inj_strhash_insert(&decl->decl_memhash, dlm->dlm_name,
	    (uintptr_t)dlm);
}

/*
 * The various declaration types - events, FMRIs, and authorities - each have
 * their own semantic validation requirements.
 */

/* No user-defined class member.  If ena isn't present, we'll generate it */
static int
inj_decl_validate_event(inj_decl_t *decl)
{
	if (inj_strhash_lookup(&decl->decl_memhash, "class") != NULL) {
		yyerror("class may not be explicitly declared\n");
		return (0);
	}

	if (inj_strhash_lookup(&decl->decl_memhash, "ena") == NULL)
		decl->decl_flags |= DECL_F_AUTOENA;

	return (1);
}

/* FMRIs must have a string scheme member */
static int
inj_decl_validate_fmri(inj_decl_t *decl)
{
	inj_declmem_t *dlm;
	inj_var_t *v;

	if ((v = inj_strhash_lookup(&decl->decl_memhash, "scheme")) == NULL) {
		yyerror("fmri declared without scheme member\n");
		return (0);
	}

	dlm = inj_hash_get_cookie(v);
	if (dlm->dlm_type != MEMTYPE_STRING) {
		yyerror("scheme member must be a string\n");
		return (0);
	}

	return (1);
}

/*ARGSUSED*/
static int
inj_decl_validate_nop(inj_decl_t *decl)
{
	return (1);
}

void
inj_decl_finish(inj_decl_t *decl, const char *name, inj_itemtype_t type)
{
	static int (*const validators[])(inj_decl_t *) = {
		inj_decl_validate_event,
		inj_decl_validate_fmri,
		inj_decl_validate_nop,	/* no validation for auth */
		inj_decl_validate_nop	/* no validation for lists */
	};

	inj_hash_t *hash = item2hash(type);
	inj_var_t *v;

	decl->decl_name = name;
	decl->decl_type = type;

	if (!validators[type](decl)) {
		inj_decl_destroy(decl);
		return;
	}

	if ((v = inj_strhash_lookup(hash, name)) != NULL) {
		inj_decl_t *other = inj_hash_get_cookie(v);

		yyerror("duplicate %s name %s (other on line %d)\n",
		    inj_item2str(type), name, other->decl_lineno);
		inj_decl_destroy(decl);
		return;
	}

	(void) inj_strhash_insert(hash, name, (uintptr_t)decl);
}
