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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DIRECTORY_PRIVATE_H
#define	_DIRECTORY_PRIVATE_H

/*
 * A suite of functions for retrieving information about objects
 * in a directory service.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	DIRECTORY_ID_NAME	"n"
#define	DIRECTORY_ID_USER	"u"
#define	DIRECTORY_ID_GROUP	"g"
#define	DIRECTORY_ID_SID	"s"

/*
 * Structure of the returned data.
 * Note that this is constructed from the bottom up; what is returned is
 * a directory_entry_list_t.
 */
typedef void *directory_datum_t;
typedef directory_datum_t *directory_attribute_value_t;
typedef struct {
	directory_attribute_value_t *attrs;
	directory_error_t err;
} directory_entry_t;
typedef directory_entry_t *directory_entry_list_t;

/*
 * Retrieve information about a user or group.  By way of analogy to exec(2),
 * the _v variants accept a list of attributes as an array, while
 * the _l variants accept the attribute list as arguments.
 * All variations accept a list of identifiers, and return a
 * directory_entry_list_t in the same order.  The length of the list of user
 * identifiers can be specified either explicitly, or by a terminating
 * NULL if the associated count is zero.  Attributes are returned in the
 * order they were requested, with missing attributes yielding NULL
 * entries.
 */
directory_error_t directory_get_v(directory_t d, directory_entry_list_t *ret,
    char **ids, int nids, char *types, char **attrlist);

directory_error_t directory_get_l(directory_t d, directory_entry_list_t *ret,
    char **ids, int nids, char *types, char *attr1, ...);

/*
 * Free the data structure returned by directory_get_by*().
 *
 * Does nothing if list==NULL.
 */
void directory_free(directory_entry_list_t list);

/* Return the number of bytes in a directory_datum_t */
size_t directory_datum_len(directory_datum_t d);

/*
 * Search a list, case-insensitively, for a string
 */
boolean_t is_in_list(char **list, char *value);

/*
 * Examine an objectClass list and distill it into a bitmap of "interesting"
 * classes.
 */
uint64_t class_bitmap(char **objectClass);

#ifdef __cplusplus
}
#endif

#endif /* _DIRECTORY_PRIVATE_H */
