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

/*
 * After having been declared, events, FMRIs and authorities must be defined
 * (instantiated) before they can be used as the subjects of commands.
 */

#include <sys/sysmacros.h>
#include <libnvpair.h>
#include <string.h>
#include <assert.h>

#include <inj_event.h>
#include <inj_err.h>
#include <inj_lex.h>
#include <inj_string.h>
#include <inj.h>

static inj_hash_t inj_defns[3];
static int inj_defns_initialized;

/* Intrinsics (signed and unsigned integer integer constants) */
typedef struct intr {
	uchar_t ei_signed;
	uchar_t ei_width;
} intr_t;

static inj_hash_t *
item2hash(inj_itemtype_t item)
{
	int i;

	assert(item >= 0 && item < sizeof (inj_defns) / sizeof (inj_hash_t));

	if (!inj_defns_initialized) {
		for (i = 0; i < sizeof (inj_defns) / sizeof (inj_hash_t); i++)
			inj_strhash_create(&inj_defns[i]);
		inj_defns_initialized = 1;
	}

	return (&inj_defns[item]);
}

inj_defn_t *
inj_defn_lookup(const char *name, inj_memtype_t type)
{
	inj_hash_t *hash = item2hash(inj_mem2item(type));
	inj_var_t *v;

	if ((v = inj_strhash_lookup(hash, name)) == NULL)
		return (NULL);

	return (inj_hash_get_cookie(v));
}

static void
inj_defn_destroy_memlist(inj_defnmem_t *m)
{
	inj_defnmem_t *n;

	for (/* */; m != NULL; m = n) {
		n = inj_list_next(m);

		switch (m->dfm_type) {
		case DEFNMEM_ARRAY:
		case DEFNMEM_LIST:
			inj_defn_destroy_memlist(inj_list_next(&m->dfm_list));
			break;
		default:
			inj_strfree(m->dfm_str);
		}
	}
}

void
inj_defn_destroy(inj_defn_t *defn)
{
	if (defn->defn_name != NULL)
		inj_strfree(defn->defn_name);

	nvlist_free(defn->defn_nvl);

	inj_defn_destroy_memlist(inj_list_next(&defn->defn_members));
}

static inj_defnmem_t *
inj_defn_mem_create_common(inj_defnmemtype_t type)
{
	inj_defnmem_t *dfm = inj_zalloc(sizeof (inj_defnmem_t));

	dfm->dfm_type = type;
	dfm->dfm_lineno = yylineno;

	return (dfm);
}

inj_defnmem_t *
inj_defn_mem_create(const char *str, inj_defnmemtype_t type)
{
	inj_defnmem_t *dfm = inj_defn_mem_create_common(type);

	dfm->dfm_str = str;

	return (dfm);
}

inj_defnmem_t *
inj_defn_mem_create_list(inj_defn_t *list, inj_defnmemtype_t type)
{
	inj_defnmem_t *dfm = inj_defn_mem_create_common(type);

	dfm->dfm_list = list->defn_members;

	inj_free(list, sizeof (inj_defn_t));

	return (dfm);
}

inj_defn_t *
inj_defn_create(inj_defnmem_t *dfm)
{
	inj_defn_t *defn = inj_zalloc(sizeof (inj_defn_t));

	defn->defn_lineno = yylineno;

	inj_list_append(&defn->defn_members, dfm);

	return (defn);
}

void
inj_defn_addmem(inj_defn_t *defn, inj_defnmem_t *dfm)
{
	inj_list_append(&defn->defn_members, dfm);
}

/*
 * Validate the dimensions of an array.  If the declared array size was zero,
 * accept (and return) whatever the definition used.  If fewer cells were
 * defined than were declared, return the declared size - the calling code will
 * fill the remaining cells with zeros.  The definition of more than the
 * declared number of cells triggers an error.  We print and error message in
 * this case and return the declared number.  This will allow processing to
 * continue.  The act of emitting the error will guarantee that we never
 * pass from parsing to program execution.
 */
static size_t
array_dim_check(inj_declmem_t *dlm, inj_defnmem_t *dfm)
{
	inj_list_t *l;
	size_t dfnelems;

	for (dfnelems = 0, l = inj_list_next(&dfm->dfm_list); l != NULL;
	    l = inj_list_next(l), dfnelems++);

	if (dlm->dlm_arrdim != 0 && dlm->dlm_arrdim != dfnelems) {
		yyerror(" %d: defined array has %d elements, expected %d\n",
		    dfm->dfm_lineno, dfnelems, dlm->dlm_arrdim);
		dfnelems = dlm->dlm_arrdim;
	}

	return (MAX(dfnelems, dlm->dlm_arrdim));
}

/*
 * The inj_defn_memcmp_* routines serve two purposes.  First, they compare a
 * given defined member with the corresponding declared member, signalling an
 * error if the two are incompatible.
 *
 * Assuming that validation succeeds, an entry is added to the passed nvlist
 * for the defined member.
 */

/* Used to ease signed and unsigned integer validation */
static const intr_t inj_intrinsics[] = {
	{ 0, 0 }, /* MEMTYPE_UNKNOWN */
	{ 1, 8 }, { 1, 16 }, { 1, 32 }, { 1, 64 },
	{ 0, 8 }, { 0, 16 }, { 0, 32 }, { 0, 64 }
};

static int
inj_defn_memcmp_signed(const intr_t *intr, inj_declmem_t *dlm,
    inj_defnmem_t *dfm, nvlist_t *nvl)
{
	longlong_t val;

	if (dfm->dfm_type != DEFNMEM_IMM && dfm->dfm_type != DEFNMEM_IDENT)
		return (inj_set_errno(EINVAL));

	if (inj_strtoll(dfm->dfm_str, intr->ei_width, &val) < 0)
		return (-1); /* errno is set for us */

	switch (dlm->dlm_type) {
	case MEMTYPE_INT8:
		errno = nvlist_add_int8(nvl, (char *)dlm->dlm_name,
		    (int8_t)val);
		break;
	case MEMTYPE_INT16:
		errno = nvlist_add_int16(nvl, (char *)dlm->dlm_name,
		    (int16_t)val);
		break;
	case MEMTYPE_INT32:
		errno = nvlist_add_int32(nvl, (char *)dlm->dlm_name,
		    (int32_t)val);
		break;
	case MEMTYPE_INT64:
		errno = nvlist_add_int64(nvl, (char *)dlm->dlm_name,
		    (int64_t)val);
	}

	if (errno != 0)
		die("failed to add member %s\n", dlm->dlm_name);

	return (0);
}

static int
inj_defn_memcmp_unsigned(const intr_t *intr, inj_declmem_t *dlm,
    inj_defnmem_t *dfm, nvlist_t *nvl)
{
	u_longlong_t val;

	if (dfm->dfm_type != DEFNMEM_IMM && dfm->dfm_type != DEFNMEM_IDENT)
		return (inj_set_errno(EINVAL));

	if (inj_strtoull(dfm->dfm_str, intr->ei_width, &val) < 0)
		return (-1); /* errno is set for us */

	switch (dlm->dlm_type) {
	case MEMTYPE_UINT8:
		errno = nvlist_add_uint8(nvl, (char *)dlm->dlm_name,
		    (uint8_t)val);
		break;
	case MEMTYPE_UINT16:
		errno = nvlist_add_uint16(nvl, (char *)dlm->dlm_name,
		    (uint16_t)val);
		break;
	case MEMTYPE_UINT32:
		errno = nvlist_add_uint32(nvl, (char *)dlm->dlm_name,
		    (uint32_t)val);
		break;
	case MEMTYPE_UINT64:
		errno = nvlist_add_uint64(nvl, (char *)dlm->dlm_name,
		    (uint64_t)val);
	}

	if (errno != 0)
		die("failed to add member %s\n", dlm->dlm_name);

	return (0);
}

/* Validate an array of (un)signed integers. */
static int
inj_defn_memcmp_intr_array(const intr_t *cont, inj_declmem_t *dlm,
    inj_defnmem_t *dfm, nvlist_t *nvl)
{
	typedef int (*adder_t)();
	static const adder_t signed_adders[] = {
		NULL, nvlist_add_int8_array, nvlist_add_int16_array,
		NULL, nvlist_add_int32_array, NULL, NULL, NULL,
		nvlist_add_int64_array
	};
	static const adder_t unsigned_adders[] = {
		NULL,
		nvlist_add_uint8_array, nvlist_add_uint16_array,
		NULL, nvlist_add_uint32_array, NULL, NULL, NULL,
		nvlist_add_uint64_array
	};

	union {
		char *a;
		int8_t *a8; uint8_t *au8;
		int16_t *a16; uint16_t *au16;
		int32_t *a32; uint32_t *au32;
		int64_t *a64; uint64_t *au64;
	} a;

	int (*adder)(nvlist_t *, const char *, char *, uint_t);
	size_t nelems;
	inj_defnmem_t *elem;
	char *arrbase, *arr;
	size_t arrsz;
	int err = 0;
	int i;

	if (dfm->dfm_type != DEFNMEM_ARRAY)
		return (inj_set_errno(EINVAL));

	/*
	 * Each nvlist array adder wants an array of its own type as input,
	 * which is reasonable, but it complicates our general implementation.
	 * We fight back with casting magic.
	 */

	nelems = array_dim_check(dlm, dfm);
	arrsz = (nelems + 1) * (cont->ei_width / NBBY);
	arrbase = inj_zalloc(arrsz);
	a.a = arr = (char *)P2ROUNDUP((uintptr_t)arrbase,
	    cont->ei_width / NBBY);

	adder = (cont->ei_signed ? signed_adders :
	    unsigned_adders)[cont->ei_width / NBBY];
	assert(adder != NULL);

	for (i = 1, elem = inj_list_next(&dfm->dfm_list); elem != NULL;
	    elem = inj_list_next(elem), i++) {
		if (elem->dfm_type != DEFNMEM_IMM &&
		    elem->dfm_type != DEFNMEM_IDENT) {
			yyerror(" %d: array cell %d is invalid\n",
			    dfm->dfm_lineno, i);
			err++;
			continue;
		}

		if (cont->ei_signed) {
			longlong_t val;

			if (inj_strtoll(elem->dfm_str, cont->ei_width,
			    &val) < 0) {
				yyerror(" %d: array cell %d %s\n",
				    dfm->dfm_lineno, i, (errno == ERANGE ?
				    "out of range for type" : "invalid"));
				err++;
				continue;
			}

			switch (cont->ei_width) {
			case 8:
				*a.a8++ = (int8_t)val;
				break;
			case 16:
				*a.a16++ = (int16_t)val;
				break;
			case 32:
				*a.a32++ = (int32_t)val;
				break;
			default:
				*a.a64++ = (int64_t)val;
			}

		} else {
			u_longlong_t val;

			if (inj_strtoull(elem->dfm_str, cont->ei_width,
			    &val) < 0) {
				yyerror(" %d: array cell %d %s\n",
				    dfm->dfm_lineno, i, (errno == ERANGE ?
				    "out of range for type" : "invalid"));
				err++;
				continue;
			}

			switch (cont->ei_width) {
			case 8:
				*a.au8++ = (uint8_t)val;
				break;
			case 16:
				*a.au16++ = (uint16_t)val;
				break;
			case 32:
				*a.au32++ = (uint32_t)val;
				break;
			default:
				*a.au64++ = (uint64_t)val;
			}
		}
	}

	if (err == 0 && (errno = adder(nvl, dlm->dlm_name, arr, nelems)) != 0)
		die("failed to add array member %s", dlm->dlm_name);

	inj_free(arrbase, arrsz);

	if (err != 0)
		return (inj_set_errno(EINVAL));

	return (0);
}

static int
bool2val(const char *str, boolean_t *valp)
{
	if (strcasecmp(str, "true") == 0)
		*valp = 1;
	else if (strcasecmp(str, "false") == 0)
		*valp = 0;
	else
		return (-1);

	return (0);
}

static int
inj_defn_memcmp_bool(inj_declmem_t *dlm, inj_defnmem_t *dfm, nvlist_t *nvl)
{
	boolean_t val;

	if (dfm->dfm_type != DEFNMEM_IDENT)
		return (inj_set_errno(EINVAL));

	if (bool2val(dfm->dfm_str, &val) < 0)
		return (inj_set_errno(EINVAL));

	if ((errno = nvlist_add_boolean_value(nvl, (char *)dlm->dlm_name,
	    val)) != 0)
		die("failed to add boolean member %s", dlm->dlm_name);

	return (0);
}

static int
inj_defn_memcmp_bool_array(inj_declmem_t *dlm, inj_defnmem_t *dfm,
    nvlist_t *nvl)
{
	inj_defnmem_t *elem;
	boolean_t *arr;
	size_t nelems, arrsz;
	int err = 0;
	int i;

	if (dfm->dfm_type != DEFNMEM_ARRAY)
		return (inj_set_errno(EINVAL));

	nelems = array_dim_check(dlm, dfm);
	arrsz = nelems * sizeof (boolean_t);
	arr = inj_zalloc(arrsz);

	for (i = 0, elem = inj_list_next(&dfm->dfm_list); elem != NULL;
	    elem = inj_list_next(elem), i++) {
		if (elem->dfm_type != DEFNMEM_IDENT) {
			yyerror(" %d: array cell %d is invalid\n",
			    dfm->dfm_lineno, i + 1);
			err++;
			continue;
		}

		if (bool2val(elem->dfm_str, &arr[i]) < 0)
			return (inj_set_errno(EINVAL));
	}

	if (err == 0 && (errno = nvlist_add_boolean_array(nvl,
	    (char *)dlm->dlm_name, arr, nelems)) != 0)
		die("failed to add boolean array member %s", dlm->dlm_name);

	inj_free(arr, arrsz);

	return (0);
}

/* Used for both strings and enums */
static int
inj_defn_memcmp_strenum(inj_declmem_t *dlm, inj_defnmem_t *dfm, nvlist_t *nvl)
{
	inj_defnmemtype_t defnmemtype = (dlm->dlm_type == MEMTYPE_ENUM ?
	    DEFNMEM_IDENT : DEFNMEM_QSTRING);
	const char *strenum = (dlm->dlm_type == MEMTYPE_ENUM ? "enum" :
	    "string");

	if (dfm->dfm_type != defnmemtype)
		return (inj_set_errno(EINVAL));

	if ((errno = nvlist_add_string(nvl, (char *)dlm->dlm_name,
	    (char *)dfm->dfm_str)) != 0)
		die("failed to add %s member %s", strenum, dlm->dlm_name);

	return (0);
}

static int
inj_defn_memcmp_strenum_array(inj_declmem_t *dlm, inj_defnmem_t *dfm,
    nvlist_t *nvl)
{
	inj_defnmemtype_t defnmemtype = (dlm->dlm_type == MEMTYPE_ENUM ?
	    DEFNMEM_IDENT : DEFNMEM_QSTRING);
	const char *strenum = (dlm->dlm_type == MEMTYPE_ENUM ? "enum" :
	    "string");

	inj_defnmem_t *elem;
	size_t nelems, arrsz;
	const char **arr;
	int err = 0;
	int i;

	if (dfm->dfm_type != DEFNMEM_ARRAY)
		return (inj_set_errno(EINVAL));

	nelems = array_dim_check(dlm, dfm);
	arrsz = nelems * sizeof (char *);
	arr = inj_zalloc(arrsz);

	for (i = 0, elem = inj_list_next(&dfm->dfm_list); elem != NULL;
	    elem = inj_list_next(elem), i++) {
		if (elem->dfm_type != defnmemtype) {
			yyerror(" %d: array cell %d is invalid\n",
			    dfm->dfm_lineno, i + 1);
			err++;
			continue;
		}

		if (dlm->dlm_type == MEMTYPE_ENUM &&
		    inj_strhash_lookup(dlm->dlm_enumvals, elem->dfm_str) ==
		    NULL) {
			yyerror(" %d: invalid enum value %s\n",
			    dfm->dfm_lineno, elem->dfm_str);
			err++;
			continue;
		}

		arr[i] = elem->dfm_str;
	}

	if (err == 0 && (errno = nvlist_add_string_array(nvl,
	    dlm->dlm_name, (char **)arr, nelems)) != 0)
		die("failed to add %s array member %s", strenum, dlm->dlm_name);

	inj_free(arr, arrsz);
	return (0);
}

/*
 * Validator for embedded lists (events, fmris, authorities, lists, etc.).
 * There are two cases to deal with here.  The user could either have provided
 * the name of a previously-defined list, in which case we just make a copy of
 * said list for insertion into ours.  Alternatively, the user could simply
 * define a new list here.  In that case, we recursively invoke the member
 * comparator, but against the list type for the member being defined.
 */
static nvlist_t *inj_defn_validate_memlist(inj_declmem_t *, inj_defnmem_t *);

/* Embedded definition */
static nvlist_t *
inj_defn_memcmp_sub_list(inj_declmem_t *dlm, inj_defnmem_t *dfm)
{
	inj_declmem_t *subdlm = inj_list_next(&dlm->dlm_decl->decl_members);
	inj_defnmem_t *subdfm = inj_list_next(&dfm->dfm_list);

	return (inj_defn_validate_memlist(subdlm, subdfm));
}

/* Reference to previously-defined thing */
static nvlist_t *
inj_defn_memcmp_sub_defined(inj_declmem_t *dlm, inj_defnmem_t *dfm)
{
	inj_defn_t *subdefn;
	nvlist_t *new;

	if ((subdefn = inj_defn_lookup(dfm->dfm_str, dlm->dlm_type)) == NULL) {
		yyerror(" %d: reference to undefined %s %s\n", dfm->dfm_lineno,
		    inj_mem2str(dlm->dlm_type), dfm->dfm_str);
		(void) inj_set_errno(EINVAL);
		return (NULL);
	}

	if (subdefn->defn_decl != dlm->dlm_decl) {
		yyerror(" %d: %s %s is not a(n) %s\n", dfm->dfm_lineno,
		    inj_mem2str(dlm->dlm_type), dfm->dfm_str,
		    subdefn->defn_decl->decl_name);
		(void) inj_set_errno(EINVAL);
		return (NULL);
	}

	assert(subdefn->defn_nvl != NULL);

	if ((errno = nvlist_dup(subdefn->defn_nvl, &new, 0)) != 0) {
		die("failed to duplicate %s list %s",
		    inj_item2str(subdefn->defn_decl->decl_type), dfm->dfm_str);
	}

	return (new);
}

static nvlist_t *
inj_defn_memcmp_sub_makenvl(inj_declmem_t *dlm, inj_defnmem_t *dfm)
{
	inj_defnmemtype_t dftype = dfm->dfm_type;
	inj_memtype_t dltype = dlm->dlm_type;
	nvlist_t *new = NULL;

	if (dftype == DEFNMEM_LIST)
		new = inj_defn_memcmp_sub_list(dlm, dfm);
	else if (dftype == DEFNMEM_IDENT && (dltype == MEMTYPE_EVENT ||
	    dltype == MEMTYPE_FMRI || dltype == MEMTYPE_AUTH))
		new = inj_defn_memcmp_sub_defined(dlm, dfm);
	else
		(void) inj_set_errno(EINVAL);

	return (new);
}

/* A single sub-list */
static int
inj_defn_memcmp_sub(inj_declmem_t *dlm, inj_defnmem_t *dfm, nvlist_t *nvl)
{
	nvlist_t *new;

	if ((new = inj_defn_memcmp_sub_makenvl(dlm, dfm)) == NULL)
		return (-1); /* errno is set for us */

	if ((errno = nvlist_add_nvlist(nvl, (char *)dlm->dlm_name,
	    new)) != 0)
		die("failed to add list member %s", dlm->dlm_name);

	return (0);
}

/* An array of sub-lists (for example, an array of events of a given type) */
static int
inj_defn_memcmp_sub_array(inj_declmem_t *dlm, inj_defnmem_t *dfm, nvlist_t *nvl)
{
	size_t nelems, arrsz;
	inj_defnmem_t *elem;
	nvlist_t **arr;
	int err = 0;
	int i;

	if (dfm->dfm_type != DEFNMEM_ARRAY)
		return (inj_set_errno(EINVAL));

	nelems = array_dim_check(dlm, dfm);
	arrsz = nelems * sizeof (char *);
	arr = inj_zalloc(arrsz);

	for (i = 0, elem = inj_list_next(&dfm->dfm_list); elem != NULL;
	    elem = inj_list_next(elem), i++) {
		if ((arr[i] = inj_defn_memcmp_sub_makenvl(dlm, elem)) == NULL) {
			yyerror(" %d: array cell %d is invalid\n",
			    elem->dfm_lineno, i + 1);
			err++;
			continue;
		}
	}

	if (err == 0 && (errno = nvlist_add_nvlist_array(nvl,
	    (char *)dlm->dlm_name, arr, nelems)) != 0)
		die("failed to add nvlist list member %s", dlm->dlm_name);

	inj_free(arr, arrsz);

	return (0);
}

/*
 * The declaration-definition member comparator.  Designed to recursive
 * invocation to allow for the validation of embedded/referenced lists.
 */
nvlist_t *
inj_defn_validate_memlist(inj_declmem_t *dlm, inj_defnmem_t *dfm)
{
	const intr_t *intr;
	nvlist_t *nvl;
	int rc, nmem, dlnmem, dfnmem;
	int err = 0;

	if ((errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0)
		die("failed to allocate nvl for event");

	for (nmem = 1; dlm != NULL && dfm != NULL;
	    dlm = inj_list_next(dlm), dfm = inj_list_next(dfm), nmem++) {

		switch (dlm->dlm_type) {
		case MEMTYPE_INT8:
		case MEMTYPE_INT16:
		case MEMTYPE_INT32:
		case MEMTYPE_INT64:
			intr = &inj_intrinsics[dlm->dlm_type];

			if (dlm->dlm_flags & DECLMEM_F_ARRAY) {
				rc = inj_defn_memcmp_intr_array(intr, dlm, dfm,
				    nvl);
			} else {
				rc = inj_defn_memcmp_signed(intr, dlm, dfm,
				    nvl);
			}
			break;

		case MEMTYPE_UINT8:
		case MEMTYPE_UINT16:
		case MEMTYPE_UINT32:
		case MEMTYPE_UINT64:
			intr = &inj_intrinsics[dlm->dlm_type];

			if (dlm->dlm_flags & DECLMEM_F_ARRAY) {
				rc = inj_defn_memcmp_intr_array(intr, dlm, dfm,
				    nvl);
			} else {
				rc = inj_defn_memcmp_unsigned(intr, dlm, dfm,
				    nvl);
			}
			break;

		case MEMTYPE_BOOL:
			if (dlm->dlm_flags & DECLMEM_F_ARRAY)
				rc = inj_defn_memcmp_bool_array(dlm, dfm, nvl);
			else
				rc = inj_defn_memcmp_bool(dlm, dfm, nvl);
			break;

		case MEMTYPE_STRING:
			if (dlm->dlm_flags & DECLMEM_F_ARRAY) {
				rc = inj_defn_memcmp_strenum_array(dlm, dfm,
				    nvl);
			} else
				rc = inj_defn_memcmp_strenum(dlm, dfm, nvl);
			break;

		case MEMTYPE_ENUM:
			if (dlm->dlm_flags & DECLMEM_F_ARRAY) {
				rc = inj_defn_memcmp_strenum_array(dlm, dfm,
				    nvl);
			} else
				rc = inj_defn_memcmp_strenum(dlm, dfm, nvl);
			break;

		case MEMTYPE_EVENT:
		case MEMTYPE_FMRI:
		case MEMTYPE_AUTH:
		case MEMTYPE_LIST:
			if (dlm->dlm_flags & DECLMEM_F_ARRAY)
				rc = inj_defn_memcmp_sub_array(dlm, dfm, nvl);
			else
				rc = inj_defn_memcmp_sub(dlm, dfm, nvl);
			break;

		default:
			die("unknown decl member type %d on member %s\n",
			    dlm->dlm_type, dlm->dlm_name);
		}

		if (rc < 0) {
			yyerror(" %d: %s for member %s\n", dfm->dfm_lineno,
			    (errno == ERANGE ? "value out of range" :
			    "invalid value"), dlm->dlm_name);
			err++;
		}
	}

	dlnmem = dfnmem = nmem;

	while (dlm != NULL) {
		dlm = inj_list_next(dlm);
		dlnmem++;
	}

	while (dfm != NULL) {
		dfm = inj_list_next(dfm);
		dfnmem++;
	}

	if (dlnmem != dfnmem) {
		yyerror("%d members found, expected %d", dfnmem, dlnmem);
		err++;
	}

	if (err > 0) {
		nvlist_free(nvl);
		return (NULL);
	}

	return (nvl);
}

/*
 * The members have all been defined.  Validate the members against the
 * declaration, and add it to the appropriate "defined" list.
 */
void
inj_defn_finish(inj_defn_t *defn, const char *declnm, const char *name,
    inj_itemtype_t type)
{
	inj_decl_t *decl = inj_decl_lookup(declnm, type);
	inj_hash_t *hash = item2hash(type);
	inj_declmem_t *dlm;
	inj_defnmem_t *dfm;
	inj_var_t *v;

	defn->defn_name = name;
	defn->defn_decl = decl;

	if (decl == NULL) {
		yyerror("unknown %s type %s\n", inj_item2str(type), declnm);
		inj_defn_destroy(defn);
		return;
	}

	dlm = inj_list_next(&decl->decl_members);
	dfm = inj_list_next(&defn->defn_members);

	if ((defn->defn_nvl = inj_defn_validate_memlist(dlm, dfm)) == NULL) {
		inj_defn_destroy(defn);
		return;
	}

	if (type == ITEMTYPE_EVENT) {
		if ((errno = nvlist_add_string(defn->defn_nvl, "class",
		    (char *)defn->defn_decl->decl_name)) != 0)
			die("failed to add class to %s", name);
	}

	if ((v = inj_strhash_lookup(hash, name)) != NULL) {
		inj_defn_t *other = inj_hash_get_cookie(v);

		yyerror("duplicate %s name %s (other on line %d)\n",
		    inj_item2str(type), name, other->defn_lineno);
		inj_defn_destroy(defn);
		return;
	}

	(void) inj_strhash_insert(hash, name, (uintptr_t)defn);
}
