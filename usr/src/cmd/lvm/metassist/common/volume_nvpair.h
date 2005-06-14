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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VOLUME_NVPAIR_H
#define	_VOLUME_NVPAIR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <libnvpair.h>

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_uint16(nvlist_t *attrs, char *which, uint16_t *val);

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
extern int set_uint16(nvlist_t *attrs, char *which, uint16_t val);

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_uint32(nvlist_t *attrs, char *which, uint32_t *val);

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
extern int set_uint32(nvlist_t *attrs, char *which, uint32_t val);

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_uint64(nvlist_t *attrs, char *which, uint64_t *val);

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
extern int set_uint64(nvlist_t *attrs, char *which, uint64_t val);

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
extern int set_boolean(nvlist_t *attrs, char *which, boolean_t val);

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_boolean(nvlist_t *attrs, char *which, boolean_t *boolval);

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_string(nvlist_t *attrs, char *which, char **str);

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
extern int set_string(nvlist_t *attrs, char *which, char *val);

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_uint16_array(
	nvlist_t *attrs, char *which, uint16_t **val, uint_t *nelem);

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
 * @return      ENOENT
 *              if no matching name-value pair is found
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int set_uint16_array(
	nvlist_t *attrs, char *which, uint16_t *val, uint_t nelem);

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_uint64_array(
	nvlist_t *attrs, char *which, uint64_t **val, uint_t *nelem);

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
 * @return      ENOENT
 *              if no matching name-value pair is found
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int set_uint64_array(
	nvlist_t *attrs, char *which, uint64_t *val, uint_t nelem);

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
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int get_string_array(
	nvlist_t *attrs, char *which, char ***val, uint_t *nelem);

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
 * @return      ENOENT
 *              if no matching name-value pair is found
 *
 * @return      ENOTSUP
 *              if an encode/decode method is not supported
 *
 * @return      EINVAL
 *              if there is an invalid argument
 */
extern int set_string_array(
	nvlist_t *attrs, char *which, char **val, uint_t nelem);

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_NVPAIR_H */
