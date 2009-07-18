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

/*
 * Some helper routines for directory lookup.  These offer functions that
 * you could implement yourself on top of the generic routines, but since
 * they're a common request we implement them here.  (Well, OK, we cheat a bit
 * and call an internal routine to do the dirty work to reduce code
 * duplication, but you could still implement them using the generic routines.)
 */

#include <stdio.h>
#include <string.h>
#include <libadutils.h>
#include <rpcsvc/idmap_prot.h>
#include "directory.h"
#include "directory_private.h"
#include "directory_library_impl.h"
#include "miscutils.h"
#include "sidutil.h"

/*
 * Given a username, return a text-form SID.
 *
 * The SID must be free()ed by the caller.
 *
 * d, if non-NULL, specifies an existing directory-search context.
 * If NULL, a temporary one will be created.
 */
directory_error_t
directory_sid_from_name_common(
    directory_t d,
    char *name,
    char *type,
    char **sid,
    uint64_t *classes)
{
	directory_t d1 = NULL;
	static char *attrs[] = {
		"objectSid",
		"objectClass",
		NULL,
	};
	directory_entry_t *ret_list = NULL;
	directory_error_t de;
	struct ret_sid {
		sid_t **objectSid;
		char **objectClass;
	} *ret_sid;

	/* Prep for error cases. */
	*sid = NULL;
	if (classes != NULL)
		*classes = 0;

	if (d == NULL) {
		de = directory_open(&d1);
		if (de != NULL)
			goto out;
	} else {
		d1 = d;
	}

	de = directory_get_v(d1, &ret_list, &name, 1, type, attrs);
	if (de != NULL)
		goto out;
	if (ret_list[0].err != NULL) {
		de = ret_list[0].err;
		ret_list[0].err = NULL;
		goto out;
	}

	ret_sid = (struct ret_sid *)ret_list[0].attrs;
	if (ret_sid == NULL)
		goto out;

	if (ret_sid->objectSid != NULL &&
	    ret_sid->objectSid[0] != NULL) {
		char text_sid[SID_STRSZ+1];
		sid_from_le(ret_sid->objectSid[0]);
		sid_tostr(ret_sid->objectSid[0], text_sid);
		*sid = strdup(text_sid);
		if (*sid == NULL)
			goto nomem;
	}

	if (ret_sid->objectClass != NULL &&
	    classes != NULL)
		*classes = class_bitmap(ret_sid->objectClass);

	goto out;

nomem:
	de = directory_error("ENOMEM.directory_sid_from_name_common",
	    "Insufficient memory retrieving data about SID", NULL);

out:
	directory_free(ret_list);
	if (d == NULL)
		directory_close(d1);
	return (de);
}

directory_error_t
directory_sid_from_name(
    directory_t d,
    char *name,
    char **sid,
    uint64_t *classes)
{
	return (directory_sid_from_name_common(d, name, DIRECTORY_ID_NAME, sid,
	    classes));
}

directory_error_t
directory_sid_from_user_name(directory_t d, char *name, char **sid)
{
	return (directory_sid_from_name_common(d, name, DIRECTORY_ID_USER, sid,
	    NULL));
}

directory_error_t
directory_sid_from_group_name(directory_t d, char *name, char **sid)
{
	return (directory_sid_from_name_common(d, name, DIRECTORY_ID_GROUP, sid,
	    NULL));
}

/*
 * Given a name or text-format SID, return a user@domain.
 *
 * The user@domain returned must be free()ed by the caller.
 *
 * Returns NULL and sets *name to NULL if no error occurred but the specified
 * entity does not exist.
 *
 * d, if non-NULL, specifies an existing directory-search context.
 * If NULL, a temporary one will be created.
 */
static
directory_error_t
directory_canon_common(
    directory_t d,
    char *id,
    char *id_type,
    char **canon,
    uint64_t *classes)
{
	directory_t d1 = NULL;
	directory_entry_t *ret_list = NULL;
	directory_error_t de;
	/*
	 * Attributes required to generate a canonical name, in named-list and
	 * structure form.
	 */
	static char *attrs[] = {
		"x-sun-canonicalName",
		"objectClass",
		NULL,
	};

	struct canon_name_ret {
		char **x_sun_canonicalName;
		char **objectClass;
	} *ret_name;

	/* Prep for error cases. */
	*canon = NULL;
	if (classes != NULL)
		*classes = 0;

	if (d == NULL) {
		de = directory_open(&d1);
		if (de != NULL)
			goto out;
	} else {
		d1 = d;
	}

	de = directory_get_v(d1, &ret_list, &id, 1, id_type, attrs);
	if (de != NULL)
		goto out;
	if (ret_list[0].err != NULL) {
		de = ret_list[0].err;
		ret_list[0].err = NULL;
		goto out;
	}

	ret_name = (struct canon_name_ret *)ret_list[0].attrs;
	if (ret_name == NULL)
		goto out;

	if (ret_name->x_sun_canonicalName != NULL &&
	    ret_name->x_sun_canonicalName[0] != NULL) {
		*canon = strdup(ret_name->x_sun_canonicalName[0]);
		if (*canon == NULL)
			goto nomem;
	}

	if (ret_name->objectClass != NULL &&
	    classes != NULL)
		*classes = class_bitmap(ret_name->objectClass);

	goto out;

nomem:
	de = directory_error("ENOMEM.directory_canon_common",
	    "Insufficient memory retrieving data about name", NULL);

out:
	directory_free(ret_list);
	if (d == NULL)
		directory_close(d1);
	return (de);
}

directory_error_t
directory_name_from_sid(
    directory_t d,
    char *sid,
    char **canon,
    uint64_t *classes)
{
	return (directory_canon_common(d, sid, DIRECTORY_ID_SID, canon,
	    classes));
}

directory_error_t
directory_canon_from_name(
    directory_t d,
    char *name,
    char **canon,
    uint64_t *classes)
{
	return (directory_canon_common(d, name, DIRECTORY_ID_NAME, canon,
	    classes));
}

directory_error_t
directory_canon_from_user_name(directory_t d, char *name, char **canon)
{
	return (
	    directory_canon_common(d, name, DIRECTORY_ID_USER, canon, NULL));
}

directory_error_t
directory_canon_from_group_name(directory_t d, char *name, char **canon)
{
	return (
	    directory_canon_common(d, name, DIRECTORY_ID_GROUP, canon, NULL));
}

boolean_t
is_in_list(char **list, char *val)
{
	for (; *list != NULL; list++) {
		if (strcaseeq(*list, val))
			return (B_TRUE);
	}
	return (B_FALSE);
}

uint64_t
class_bitmap(char **objectClass)
{
	uint64_t ret = 0;

	for (; *objectClass != NULL; objectClass++) {
		if (strcaseeq(*objectClass, "user") ||
		    strcaseeq(*objectClass, "posixAccount"))
			ret |= DIRECTORY_CLASS_USER;

		if (strcaseeq(*objectClass, "group") ||
		    strcaseeq(*objectClass, "posixGroup"))
			ret |= DIRECTORY_CLASS_GROUP;
	}

	return (ret);
}
