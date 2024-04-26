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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pool.h>
#include "pool_internal.h"

/*
 * libpool Value Manipulation Routines
 *
 * pool_value.c implements the value (pool_value_t) functionality for
 * libpool. The datatypes supported are: uint64_t, int64_t, double,
 * uchar_t (boolean), const char * (string). Values are used to
 * represent data stored to and retrieved from the datastore in a
 * simple discriminated union.
 *
 * Values are dynamically allocated using pool_value_alloc() and
 * destroyed using pool_value_free().
 *
 * Values may be allocated statically for internal use in
 * libpool. Statically allocated pool_value_t variables must be
 * initialised with the POOL_VALUE_INITIALIZER macro, otherwise the
 * results are unpredictable.
 *
 * A pool_value_t variable can be used to store values in any of the
 * supported datatypes.
 *
 * A pool_value_t's name and string value are limited in size to
 * PV_NAME_MAX_LEN and PV_VALUE_MAX_LEN respectively. Attempting to
 * store values which are greater than this in length will fail with a
 * POE_BADPARAM error.
 */

/*
 * Get the uint64_t data held by the value. If the data type isn't
 * uint64_t return PO_FAIL and set pool_error to be POE_BAD_PROP_TYPE.
 */
int
pool_value_get_uint64(const pool_value_t *pv, uint64_t *result)
{
	if (pv->pv_class != POC_UINT) {
		pool_seterror(POE_BAD_PROP_TYPE);
		return (PO_FAIL);
	}
	*result = pv->pv_u.u;
	return (PO_SUCCESS);
}

/*
 * Get the int64_t data held by the value. If the data type isn't
 * int64_t return PO_FAIL and set pool_error to be POE_BAD_PROP_TYPE.
 */
int
pool_value_get_int64(const pool_value_t *pv, int64_t *result)
{
	if (pv->pv_class != POC_INT) {
		pool_seterror(POE_BAD_PROP_TYPE);
		return (PO_FAIL);
	}
	*result = pv->pv_u.i;
	return (PO_SUCCESS);
}

/*
 * Get the double data held by the value. If the data type isn't
 * double return PO_FAIL and set pool_error to be POE_BAD_PROP_TYPE.
 */

int
pool_value_get_double(const pool_value_t *pv, double *result)
{
	if (pv->pv_class != POC_DOUBLE) {
		pool_seterror(POE_BAD_PROP_TYPE);
		return (PO_FAIL);
	}
	*result = pv->pv_u.d;
	return (PO_SUCCESS);
}

/*
 * Get the boolean data held by the value. If the data type isn't
 * boolean return PO_FAIL and set pool_error to be POE_BAD_PROP_TYPE.
 */
int
pool_value_get_bool(const pool_value_t *pv, uchar_t *result)
{
	if (pv->pv_class != POC_BOOL) {
		pool_seterror(POE_BAD_PROP_TYPE);
		return (PO_FAIL);
	}
	*result = pv->pv_u.b;
	return (PO_SUCCESS);
}

/*
 * Get the string data held by the value. If the data type isn't
 * string return PO_FAIL and set pool_error to be POE_BAD_PROP_TYPE.
 */
int
pool_value_get_string(const pool_value_t *pv, const char **result)
{
	if (pv->pv_class != POC_STRING) {
		pool_seterror(POE_BAD_PROP_TYPE);
		return (PO_FAIL);
	}
	*result = pv->pv_u.s;
	return (PO_SUCCESS);
}

/*
 * Get the type of the data held by the value. If the value has never
 * been used to store data, then the type is POC_INVAL.
 */
pool_value_class_t
pool_value_get_type(const pool_value_t *pv)
{
	return (pv->pv_class);
}

/*
 * Set the value's data to the supplied uint64_t data. Update the type
 * of the value data to POC_UINT.
 */
void
pool_value_set_uint64(pool_value_t *pv, uint64_t val)
{
	if (pv->pv_class == POC_STRING)
		atom_free(pv->pv_u.s);
	pv->pv_class = POC_UINT;
	pv->pv_u.u = val;
}

/*
 * Set the value's data to the supplied int64_t data. Update the type
 * of the value data to POC_INT.
 */
void
pool_value_set_int64(pool_value_t *pv, int64_t val)
{
	if (pv->pv_class == POC_STRING)
		atom_free(pv->pv_u.s);
	pv->pv_class = POC_INT;
	pv->pv_u.i = val;
}

/*
 * Set the value's data to the supplied double data. Update the type
 * of the value data to POC_DOUBLE.
 */

void
pool_value_set_double(pool_value_t *pv, double val)
{
	if (pv->pv_class == POC_STRING)
		atom_free(pv->pv_u.s);
	pv->pv_class = POC_DOUBLE;
	pv->pv_u.d = val;
}

/*
 * Set the value's data to the supplied uchar_t data. Update the type
 * of the value data to POC_BOOL.
 */
void
pool_value_set_bool(pool_value_t *pv, uchar_t val)
{
	if (pv->pv_class == POC_STRING)
		atom_free(pv->pv_u.s);
	pv->pv_class = POC_BOOL;
	pv->pv_u.b = !!val;	/* Lock value at 0 or 1 */
}

/*
 * Try to make an internal copy of the val, returning PO_SUCCESS or
 * PO_FAIL if the copy works or fails.
 */
int
pool_value_set_string(pool_value_t *pv, const char *val)
{
	if (pv->pv_class == POC_STRING)
		atom_free(pv->pv_u.s);
	pv->pv_class = POC_STRING;
	if (val == NULL || strlen(val) >= PV_VALUE_MAX_LEN) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	} else {
		if ((pv->pv_u.s = atom_string(val)) == NULL)
			return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Allocate a pool_value_t structure and initialise it to 0. Set the
 * type to POC_INVAL and return a pointer to the new pool_value_t. If
 * memory allocation fails, set POE_SYSTEM and return NULL.
 */
pool_value_t *
pool_value_alloc(void)
{
	pool_value_t *val;

	if ((val = malloc(sizeof (pool_value_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	(void) memset(val, 0, sizeof (pool_value_t));
	val->pv_class = POC_INVAL;
	return (val);
}

/*
 * Free any atoms associated with the value and then free the value
 * itself.
 */
void
pool_value_free(pool_value_t *pv)
{
	if (pv->pv_name)
		atom_free(pv->pv_name);
	if (pv->pv_class == POC_STRING)
		atom_free(pv->pv_u.s);
	free(pv);
}

/*
 * Return a pointer to the name of the value. This may be NULL if the
 * name has never been set.
 */
const char *
pool_value_get_name(const pool_value_t *pv)
{
	return (pv->pv_name);
}

/*
 * Set the name of the value to the supplied name.
 */
int
pool_value_set_name(pool_value_t *pv, const char *name)
{
	if (name == NULL || strlen(name) >= PV_NAME_MAX_LEN) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	} else {
		if (pv->pv_name)
			atom_free(pv->pv_name);
		if ((pv->pv_name = atom_string(name)) == NULL)
			return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Use the supplied nvpair_t to set the name, type and value of the
 * supplied pool_value_t.
 *
 * Return: PO_SUCCESS/PO_FAIL
 */
int
pool_value_from_nvpair(pool_value_t *pv, nvpair_t *pn)
{
	uchar_t bval;
	uint64_t uval;
	int64_t ival;
	double dval;
	uint_t nelem;
	uchar_t *dval_b;
	char *sval;

	if (pool_value_set_name(pv, nvpair_name(pn)) != PO_SUCCESS)
		return (PO_FAIL);
	switch (nvpair_type(pn)) {
	case DATA_TYPE_BYTE:
		if (nvpair_value_byte(pn, &bval) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		pool_value_set_bool(pv, bval);
		break;
	case DATA_TYPE_BYTE_ARRAY:
		if (nvpair_value_byte_array(pn, &dval_b, &nelem) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		(void) memcpy(&dval, dval_b, sizeof (double));
		pool_value_set_double(pv, dval);
		break;
	case DATA_TYPE_INT64:
		if (nvpair_value_int64(pn, &ival) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		pool_value_set_int64(pv, ival);
		break;
	case DATA_TYPE_UINT64:
		if (nvpair_value_uint64(pn, &uval) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		pool_value_set_uint64(pv, uval);
		break;
	case DATA_TYPE_STRING:
		if (nvpair_value_string(pn, &sval) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		if (pool_value_set_string(pv, sval) != PO_SUCCESS)
			return (PO_FAIL);
		break;
	default:
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Check to see if the values held by two supplied values are
 * equal. First compare the pointers to see if we are comparing to
 * ourselves, if we are return PO_TRUE. If not, get the types and
 * ensure they match, if they don't return PO_FALSE. Then do a type
 * specific comparison returning PO_TRUE or PO_FALSE accordingly.
 */
int
pool_value_equal(pool_value_t *pv1, pool_value_t *pv2)
{
	uint64_t uval1, uval2;
	int64_t ival1, ival2;
	double dval1, dval2;
	uchar_t bval1, bval2;
	const char *sval1, *sval2;
	pool_value_class_t type;

	if (pv1 == pv2) /* optimisation */
		return (PO_TRUE);

	type = pool_value_get_type(pv1);
	if (type != pool_value_get_type(pv2))
		return (PO_FALSE);

	switch (type) {
		case POC_UINT:
			(void) pool_value_get_uint64(pv1, &uval1);
			(void) pool_value_get_uint64(pv2, &uval2);
			if (uval1 == uval2)
				return (PO_TRUE);
			break;
		case POC_INT:
			(void) pool_value_get_int64(pv1, &ival1);
			(void) pool_value_get_int64(pv2, &ival2);
			if (ival1 == ival2)
				return (PO_TRUE);
			break;
		case POC_DOUBLE:
			(void) pool_value_get_double(pv1, &dval1);
			(void) pool_value_get_double(pv2, &dval2);
			if (dval1 == dval2)
				return (PO_TRUE);
			break;
		case POC_BOOL:
			(void) pool_value_get_bool(pv1, &bval1);
			(void) pool_value_get_bool(pv2, &bval2);
			if (bval1 == bval2)
				return (PO_TRUE);
			break;
		case POC_STRING:
			(void) pool_value_get_string(pv1, &sval1);
			(void) pool_value_get_string(pv2, &sval2);
			if (strcmp(sval1, sval2) == 0)
				return (PO_TRUE);
			break;
	}
	return (PO_FALSE);
}

#ifdef DEBUG
/*
 * Trace pool_value_t details using pool_dprintf
 */
void
pool_value_dprintf(const pool_value_t *pv)
{
	const char *class_name[] = {
		"POC_UINT",
		"POC_INT",
		"POC_DOUBLE",
		"POC_BOOL",
		"POC_STRING"
	};

	pool_dprintf("name: %s\n", pv->pv_name ? pv->pv_name : "NULL");
	if (pv->pv_class >= POC_UINT && pv->pv_class <= POC_STRING)
		pool_dprintf("type: %s\n", class_name[pv->pv_class]);
	else
		pool_dprintf("type: POC_INVAL\n");
	switch (pv->pv_class) {
	case POC_UINT:
		pool_dprintf("value: %llu\n", pv->pv_u.u);
		break;
	case POC_INT:
		pool_dprintf("value: %lld\n", pv->pv_u.i);
		break;
	case POC_DOUBLE:
		pool_dprintf("value: %f\n", pv->pv_u.d);
		break;
	case POC_BOOL:
		pool_dprintf("value: %s\n", pv->pv_u.b ? "true" : "false");
		break;
	case POC_STRING:
		pool_dprintf("value: %s\n", pv->pv_u.s);
		break;
	default:
		pool_dprintf("value: invalid\n");
		break;
	}
}
#endif	/* DEBUG */
