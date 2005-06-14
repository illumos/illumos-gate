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

#ifndef _VOLUME_STRING_H
#define	_VOLUME_STRING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The length of the string when the longest long long is converted to
 * a string
 */
#define	LONG_LONG_STR_SIZE	128

#define	BYTES_PER_BLOCK 512
#define	BYTES_PER_KILOBYTE 1024
#define	BYTES_PER_MEGABYTE 1024 * 1024
#define	BYTES_PER_GIGABYTE 1024 * 1024 * 1024
#define	BYTES_PER_TERABYTE (uint64_t)1024 * 1024 * 1024 * 1024

/*
 * Describes units when converting from bytes to string and back.
 */
typedef struct {
    char *unit_str;
    uint64_t bytes_per_unit;
} units_t;

/* All-inclusive valid size units */
extern units_t universal_units[];

/*
 * Concatenates a list of strings.  The result must be free()d.
 *
 * @param       numargs
 *              The number of strings to concatenate.
 *
 * @param       ...
 *              The strings (type char *) to concatenate.
 *
 * @return      the concatenated string
 *              if succesful
 *
 * @return      NULL
 *              if memory could not be allocated
 */
extern char *stralloccat(int numargs, ...);

/*
 * Convert the given string to a uint16_t, verifying that the value
 * does not exceed the lower or upper bounds of a uint16_t.
 *
 * @param       str
 *              the string to convert
 *
 * @param       num
 *              the addr of the uint16_t
 *
 * @return      0
 *              if the given string was converted to a uint16_t
 *
 * @return      -1
 *              if the string could could not be converted to a number
 *
 * @return      -2
 *              if the converted number exceeds the lower or upper
 *              bounds of a uint16_t
 */
extern int str_to_uint16(char *str, uint16_t *num);

/*
 * Converts the given long long into a string.  This string must be
 * freed.
 *
 * @param       num
 *              the long long to convert
 *
 * @param       str
 *              the addr of the string
 *
 * @return      0
 *              if successful
 *
 * @return      ENOMEM
 *              if the physical limits of the system are exceeded by
 *              size bytes of memory which cannot be allocated
 *
 * @return      EAGAIN
 *              if there is not enough memory available to allocate
 *              size bytes of memory
 */
extern int ll_to_str(long long num, char **str);

/*
 * Convert a size specification to bytes.
 *
 * @param       str
 *              a size specification strings of the form
 *              <value><units>, where valid <units> are specified by
 *              the units argument and <value> is the (floating-point)
 *              multiplier of the units
 *
 * @param       bytes
 *              RETURN: the result of converting the given size string
 *              to bytes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
extern int sizestr_to_bytes(char *str, uint64_t *bytes, units_t units[]);

/*
 * Convert bytes to a size specification string.
 *
 * @param       bytes
 *              the number of bytes
 *
 * @param       str
 *              RETURN: a size specification strings of the form
 *              <value><units>, where valid <units> are specified by
 *              the units argument and <value> is the (floating-point)
 *              multiplier of the units.  This string must be freed.
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
extern int bytes_to_sizestr(
	uint64_t bytes, char **str, units_t units[], boolean_t round);

/*
 * Appends a copy of the given string to the given string array,
 * ensuring that the last element in the array is NULL.  This array
 * must be freed via free_string_array.
 *
 * Note when an error occurs and NULL is returned, array is not freed.
 * Subsequently callers should save a pointer to the original array
 * until success is verified.
 *
 * @param       array
 *              the array to append to, or NULL to create a new array
 *
 * @param       str
 *              the string to copy and add to the array
 *
 * @return      a pointer to the realloc'd (and possibly moved) array
 *              if succesful
 *
 * @return      NULL
 *              if unsuccesful
 */
extern char ** append_to_string_array(char **array, char *str);

/*
 * Frees each element of the given string array, then frees the array
 * itself.
 *
 * @param       array
 *              a NULL-terminated string array
 */
extern void free_string_array(char **array);

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_STRING_H */
