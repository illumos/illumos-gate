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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <string.h>
#include "volume_nvpair.h"
#include "volume_error.h"

/*
 * ******************************************************************
 *
 * Function prototypes
 *
 * ******************************************************************
 */

static nvpair_t *nvlist_walk_nvpair(nvlist_t *nvl,
    const char *name, data_type_t type, nvpair_t *nvp);

/*
 * ******************************************************************
 *
 * External functions
 *
 * ******************************************************************
 */

/*
 * Get the named uint16 from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              RETURN: the value of the requested uint16
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_uint16(
	nvlist_t *attrs,
	char *which,
	uint16_t *val)
{
	int error;
	nvpair_t *match =
	    nvlist_walk_nvpair(attrs, which, DATA_TYPE_UINT16, NULL);

	if (match == NULL) {
	    error = ENOENT;
	} else {
	    error = nvpair_value_uint16(match, val);
	}

	return (error);
}

/*
 * Set the named uint16 in the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value to set
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_uint16(
	nvlist_t *attrs,
	char *which,
	uint16_t val)
{
	int error = 0;

	if ((error = nvlist_add_uint16(attrs, which, val)) != 0) {
	    volume_set_error(
		gettext("nvlist_add_int16(%s) failed: %d\n"), which, error);
	}

	return (error);
}

/*
 * Get the named uint32 from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              RETURN: the value of the requested uint32
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_uint32(
	nvlist_t *attrs,
	char *which,
	uint32_t *val)
{
	int error;
	nvpair_t *match =
	    nvlist_walk_nvpair(attrs, which, DATA_TYPE_UINT32, NULL);

	if (match == NULL) {
	    error = ENOENT;
	} else {
	    error = nvpair_value_uint32(match, val);
	}

	return (error);
}

/*
 * Set the named uint32 in the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value to set
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_uint32(
	nvlist_t *attrs,
	char *which,
	uint32_t val)
{
	int error = 0;

	if ((error = nvlist_add_uint32(attrs, which, val)) != 0) {
	    volume_set_error(
		gettext("nvlist_add_int32(%s) failed: %d\n"), which, error);
	}

	return (error);
}

/*
 * Get the named uint64 from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              RETURN: the value of the requested uint64
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_uint64(
	nvlist_t *attrs,
	char *which,
	uint64_t *val)
{
	int error;
	nvpair_t *match =
	    nvlist_walk_nvpair(attrs, which, DATA_TYPE_UINT64, NULL);

	if (match == NULL) {
	    error = ENOENT;
	} else {
	    error = nvpair_value_uint64(match, val);
	}

	return (error);
}

/*
 * Set the named uint64 in the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value to set
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_uint64(
	nvlist_t *attrs,
	char *which,
	uint64_t val)
{
	int error = 0;

	if ((error = nvlist_add_uint64(attrs, which, val)) != 0) {
	    volume_set_error(
		gettext("nvlist_add_int64(%s) failed: %d\n"), which, error);
	}

	return (error);
}

/*
 * Set the named boolean in the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value to set
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_boolean(
	nvlist_t *attrs,
	char *which,
	boolean_t val)
{
	/*
	 * Use set_uint16 to distinguish "attr = B_FALSE" from
	 * "attribute unset".
	 */
	return (set_uint16(attrs, which, val == B_TRUE ? 1 : 0));
}

/*
 * Get the named boolean from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       boolval
 *              RETURN: the value of the requested boolean
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_boolean(
	nvlist_t *attrs,
	char *which,
	boolean_t *boolval)
{
	int error;
	uint16_t val;

	/*
	 * Use get_uint16 to distinguish "attr = B_FALSE" from
	 * "attribute unset".
	 */
	if ((error = get_uint16(attrs, which, &val)) == 0) {
	    *boolval = (val ? B_TRUE : B_FALSE);
	}

	return (error);
}

/*
 * Get the named string from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       str
 *              RETURN: the requested string
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_string(
	nvlist_t *attrs,
	char *which,
	char **str)
{
	int error;
	nvpair_t *match =
	    nvlist_walk_nvpair(attrs, which, DATA_TYPE_STRING, NULL);

	if (match == NULL) {
	    error = ENOENT;
	} else {
	    error = nvpair_value_string(match, str);
	}

	return (error);
}

/*
 * Set the named string in the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value to set
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_string(
	nvlist_t *attrs,
	char *which,
	char *val)
{
	int error = 0;

	if ((error = nvlist_add_string(attrs, which, val)) != 0) {
	    volume_set_error(
		gettext("nvlist_add_string(%s) failed: %d\n"), which, error);
	}

	return (error);
}

/*
 * Get the named uint16 array from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              RETURN: the value of the requested uint16 array
 *
 * @param       nelem
 *              RETURN: the number of elements in the array
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_uint16_array(
	nvlist_t *attrs,
	char *which,
	uint16_t **val,
	uint_t *nelem)
{
	int error;
	nvpair_t *match =
	    nvlist_walk_nvpair(attrs, which, DATA_TYPE_UINT16_ARRAY, NULL);

	if (match == NULL) {
	    error = ENOENT;
	} else {
	    error = nvpair_value_uint16_array(match, val, nelem);
	}

	return (error);
}

/*
 * Set the named uint16 array from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value of the requested uint16 array
 *
 * @param       nelem
 *              the number of elements in the array
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_uint16_array(
	nvlist_t *attrs,
	char *which,
	uint16_t *val,
	uint_t nelem)
{
	int error = 0;

	if ((error = nvlist_add_uint16_array(
	    attrs, which, val, nelem)) != 0) {
	    volume_set_error(
		gettext("nvlist_add_uint16_array(%s) failed: %d.\n"),
		which, error);
	}

	return (error);
}

/*
 * Get the named uint64 array from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              RETURN: the value of the requested uint64 array
 *
 * @param       nelem
 *              RETURN: the number of elements in the array
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_uint64_array(
	nvlist_t *attrs,
	char *which,
	uint64_t **val,
	uint_t *nelem)
{
	int error;
	nvpair_t *match =
	    nvlist_walk_nvpair(attrs, which, DATA_TYPE_UINT64_ARRAY, NULL);

	if (match == NULL) {
	    error = ENOENT;
	} else {
	    error = nvpair_value_uint64_array(match, val, nelem);
	}

	return (error);
}

/*
 * Set the named uint64 array from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value of the requested uint64 array
 *
 * @param       nelem
 *              the number of elements in the array
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_uint64_array(
	nvlist_t *attrs,
	char *which,
	uint64_t *val,
	uint_t nelem)
{
	int error = 0;

	if ((error = nvlist_add_uint64_array(
	    attrs, which, val, nelem)) != 0) {
	    volume_set_error(
		gettext("nvlist_add_uint64_array(%s) failed: %d.\n"),
		which, error);
	}

	return (error);
}

/*
 * Get the named string array from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              RETURN: the value of the requested string array
 *
 * @param       nelem
 *              RETURN: the number of elements in the array
 *
 * @return      0
 *              if successful
 *
 * @return      ENOENT
 *              if no matching name-value pair is found
 */
int
get_string_array(
	nvlist_t *attrs,
	char *which,
	char ***val,
	uint_t *nelem)
{
	int error;
	nvpair_t *match =
	    nvlist_walk_nvpair(attrs, which, DATA_TYPE_STRING_ARRAY, NULL);

	if (match == NULL) {
	    error = ENOENT;
	} else {
	    error = nvpair_value_string_array(match, val, nelem);
	}

	return (error);
}

/*
 * Set the named string array from the given nvlist_t.
 *
 * @param       attrs
 *              the nvlist_t to search
 *
 * @param       which
 *              the string key for this element in the list
 *
 * @param       val
 *              the value of the requested string array
 *
 * @param       nelem
 *              the number of elements in the array
 *
 * @return      0
 *              if successful
 *
 * @return      EINVAL
 *              if there is an invalid argument
 *
 * @return      ENOMEM
 *              if there is insufficient memory
 */
int
set_string_array(
	nvlist_t *attrs,
	char *which,
	char **val,
	uint_t nelem)
{
	int error = 0;

	if ((error = nvlist_add_string_array(
	    attrs, which, val, nelem)) != 0) {
	    volume_set_error(
		gettext("nvlist_add_string_array(%s) failed: %d.\n"),
		which, error);
	}

	return (error);
}

/*
 * ******************************************************************
 *
 * Static functions
 *
 * ******************************************************************
 */

/*
 * Get a handle to the next nvpair with the specified name and data
 * type in the list following the given nvpair.
 *
 * Some variation of this function will likely appear in the libnvpair
 * library per 4981923.
 *
 * @param       nvl
 *              the nvlist_t to search
 *
 * @param       name
 *              the string key for the pair to find in the list, or
 *              NULL to match any name
 *
 * @param       type
 *              the data type for the pair to find in the list, or
 *              DATA_TYPE_UNKNOWN to match any type
 *
 * @param       nvp
 *              the pair to search from in the list, or NULL to search
 *              from the beginning of the list
 *
 * @return      the next nvpair in the list matching the given
 *              criteria, or NULL if no matching nvpair is found
 */
static nvpair_t *
nvlist_walk_nvpair(
	nvlist_t *nvl,
	const char *name,
	data_type_t type,
	nvpair_t *nvp)
{
	/* For each nvpair in the list following nvp... */
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {

	    /* Does this pair's name match the given name? */
	    if ((name == NULL || strcmp(nvpair_name(nvp), name) == 0) &&

		/* Does this pair's type match the given type? */
		(type == DATA_TYPE_UNKNOWN || type == nvpair_type(nvp))) {
		return (nvp);
	    }
	}

	return (NULL);
}
