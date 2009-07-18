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

#ifndef _DIRECTORY_H
#define	_DIRECTORY_H

/*
 * A suite of functions for retrieving information about objects
 * in a directory service.
 *
 * Currently it is limited to retrieving SIDs from names, and vice
 * versa.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * This bitmap is a distillation of the objectClass attribute,
 * reporting those classes that Solaris finds "interesting".
 *
 * All undefined bits are reserved and must be ignored.
 */
#define	DIRECTORY_CLASS_USER	0x0000000000000001
#define	DIRECTORY_CLASS_GROUP	0x0000000000000002

/*
 * Opaque pointer to a directory search context.
 */
typedef struct directory *directory_t;

/*
 * Opaque pointer to a structure that describes an error.
 * Note that NULL means no error.
 */
typedef struct directory_error *directory_error_t;

/*
 * Initialize a directory query session, returning in *d a directory_t
 * that should be used for query transactions.
 */
directory_error_t directory_open(directory_t *d);

/*
 * Tear down a directory query session.
 * There is an argument that this should return a directory_error_t, but
 * then what state would the directory_t be in, and what should you do
 * if you were doing the directory_close as a result of encountering an error?
 *
 * Does nothing if d==NULL.
 */
void directory_close(directory_t d);

/*
 * All directory_t functions return NULL on success or a pointer to a
 * directory_error_t structure on failure.  The caller must call
 * directory_error_free() on any non-NULL directory_error_t structures returned.
 *
 * Strings returned from the directory_error functions are are
 * invalidated when the directory_error_t itself is freed.
 */

directory_error_t directory_error(const char *code, const char *fmt, ...);

/*
 * Determines whether this directory_error_t is an instance of the
 * particular error, or a subclass of that error.
 */
boolean_t directory_error_is_instance_of(directory_error_t de,
    char *error_string);

/*
 * Returns a printable version of this directory_error_t, suitable for
 * human consumption.
 *
 * The string returned is valid as long as the directory_error_t itself is
 * valid, and is freed when the directory_error_t is freed.
 */
const char *directory_error_printable(directory_error_t de);

/*
 * Returns the error code for the particular error, as a string.
 * Note that this function should not normally be used to answer
 * the question "did error X happen", since the value returned
 * could be a subclass of X.  directory_error_is_instance_of is intended
 * to answer that question.  This function is more appropriate for
 * logging, where one would want to log the error code and the list
 * of parameters so as to allow structured analysis of the error
 * after the fact.
 *
 * The string returned is valid as long as the directory_error_t itself is
 * valid, and is freed when the directory_error_t is freed.
 */
const char *directory_error_code(directory_error_t de);

/*
 * Returns one of the parameters of the directory_error_t, or NULL if
 * the parameter does not exist.
 *
 * Note that by definition error subclasses have initial parameters
 * the same as their superclasses.
 *
 * The string returned is valid as long as the directory_error_t itself is
 * valid, and is freed when the directory_error_t is freed.
 */
const char *directory_error_param(directory_error_t de, int param);

/*
 * Frees the memory (if any) allocated for the directory_error_t.
 * This frees all strings that might have been derived from this
 * directory_error_t through directory_error_code, directory_error_printable,
 * et cetera.
 *
 * Does nothing if de==NULL.
 */
void directory_error_free(directory_error_t de);

/*
 * Utility functions to look up a SID given a name, and vice versa.
 * Caller must free() the result (sid or name, respectively).
 */
directory_error_t directory_sid_from_name(directory_t d, char *name, char **sid,
    uint64_t *classes);
directory_error_t directory_sid_from_user_name(directory_t d, char *name,
    char **sid);
directory_error_t directory_sid_from_group_name(directory_t d, char *name,
    char **sid);
directory_error_t directory_name_from_sid(directory_t d, char *sid, char **name,
    uint64_t *classes);
directory_error_t directory_canon_from_name(directory_t d, char *name,
    char **canon, uint64_t *classes);
directory_error_t directory_canon_from_user_name(directory_t d, char *name,
    char **canon);
directory_error_t directory_canon_from_group_name(directory_t d, char *name,
    char **canon);

#ifdef __cplusplus
}
#endif

#endif /* _DIRECTORY_H */
