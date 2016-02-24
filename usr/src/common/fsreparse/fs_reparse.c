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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>

#ifdef _KERNEL
#include <sys/sunddi.h>
#include <fs/fs_reparse.h>
#else
#include <string.h>
#include <limits.h>
#include <sys/fs_reparse.h>

#define	strfree(str)		free((str))
#endif

static char *reparse_skipspace(char *cp);
static int reparse_create_nvlist(const char *string, nvlist_t *nvl);
static int reparse_add_nvpair(char *token, nvlist_t *nvl);
static boolean_t reparse_validate_svctype(char *svc_str);
static int reparse_validate_create_nvlist(const char *string, nvlist_t *nvl);

/* array of characters not allowed in service type string */
static char svctype_invalid_chars[] = { '{', '}', 0 };

/*
 * reparse_init()
 *
 * Function to allocate a new name-value pair list.
 * Caller needs to call reparse_free() to free memory
 * used by the list when done.
 *
 * Return pointer to new list else return NULL.
 */
nvlist_t *
reparse_init(void)
{
	nvlist_t *nvl;

	/*
	 * Service type is unique, only one entry
	 * of each service type is allowed
	 */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0))
		return (NULL);

	return (nvl);
}

/*
 * reparse_free()
 *
 * Function to free memory of a nvlist allocated previously
 * by reparse_init().
 */
void
reparse_free(nvlist_t *nvl)
{
	nvlist_free(nvl);
}

/*
 * reparse_parse()
 *
 * Parse the specified string and populate the nvlist with the svc_types
 * and data from the 'string'.  The string could be read from the reparse
 * point symlink body. This routine will allocate memory that must be
 * freed by reparse_free().
 *
 * If ok return 0 and the nvlist is populated, otherwise return error code.
 */
int
reparse_parse(const char *string, nvlist_t *nvl)
{
	int err;

	if (string == NULL || nvl == NULL)
		return (EINVAL);

	if ((err = reparse_validate(string)) != 0)
		return (err);

	if ((err = reparse_create_nvlist(string, nvl)) != 0)
		return (err);

	return (0);
}

static char *
reparse_skipspace(char *cp)
{
	while ((*cp) && (*cp == ' ' || *cp == '\t'))
		cp++;
	return (cp);
}

static boolean_t
reparse_validate_svctype(char *svc_str)
{
	int nx, ix, len;

	if (svc_str == NULL)
		return (B_FALSE);

	len = strlen(svc_str);
	for (ix = 0; ix < len; ix++) {
		for (nx = 0; nx < sizeof (svctype_invalid_chars); nx++) {
			if (svc_str[ix] == svctype_invalid_chars[nx])
				return (B_FALSE);
		}
	}
	return (B_TRUE);
}

static boolean_t
reparse_validate_svc_token(char *svc_token)
{
	char save_c, *cp;

	if (svc_token == NULL)
		return (B_FALSE);
	if ((cp = strchr(svc_token, ':')) == NULL)
		return (B_FALSE);

	save_c = *cp;
	*cp = '\0';

	/*
	 * make sure service type and service data are non-empty string.
	 */
	if (strlen(svc_token) == 0 || strlen(cp + 1) == 0) {
		*cp = save_c;
		return (B_FALSE);
	}

	*cp = save_c;
	return (B_TRUE);
}

/*
 * Format of reparse data:
 * @{REPARSE@{servicetype:data} [@{servicetype:data}] ...}
 * REPARSE_TAG_STR@{REPARSE_TOKEN} [@{REPARSE_TOKEN}] ... REPARSE_TAG_END
 *
 * Validating reparse data:
 *	. check for valid length of reparse data
 *	. check for valid reparse data format
 * Return 0 if OK else return error code.
 */
int
reparse_validate(const char *string)
{
	return (reparse_validate_create_nvlist(string, NULL));
}

/*
 * reparse_validate_create_nvlist
 *
 * dual-purpose function:
 *     . Validate a reparse data string.
 *     . Validate a reparse data string and parse the data
 *	 into a nvlist.
 */
static int
reparse_validate_create_nvlist(const char *string, nvlist_t *nvl)
{
	int err, tcnt;
	char *reparse_data, save_c, save_e, *save_e_ptr, *cp, *s_str, *e_str;

	if (string == NULL)
		return (EINVAL);

	if (strlen(string) >= MAXREPARSELEN)
		return (ENAMETOOLONG);

	if ((reparse_data = strdup(string)) == NULL)
		return (ENOMEM);

	/* check FS_REPARSE_TAG_STR */
	if (strncmp(reparse_data, FS_REPARSE_TAG_STR,
	    strlen(FS_REPARSE_TAG_STR))) {
		strfree(reparse_data);
		return (EINVAL);
	}

	/* locate FS_REPARSE_TAG_END_CHAR */
	if ((cp = strrchr(reparse_data, FS_REPARSE_TAG_END_CHAR)) == NULL) {
		strfree(reparse_data);
		return (EINVAL);
	}
	save_e = *cp;
	save_e_ptr = cp;
	*cp = '\0';

	e_str = cp;
	cp++;		/* should point to NULL, or spaces */

	cp = reparse_skipspace(cp);
	if (*cp) {
		*save_e_ptr = save_e;
		strfree(reparse_data);
		return (EINVAL);
	}

	/* skip FS_REPARSE_TAG_STR */
	s_str = reparse_data + strlen(FS_REPARSE_TAG_STR);

	/* skip spaces after FS_REPARSE_TAG_STR */
	s_str = reparse_skipspace(s_str);

	tcnt = 0;
	while (s_str < e_str) {
		/* check FS_TOKEN_START_STR */
		if (strncmp(s_str, FS_TOKEN_START_STR,
		    strlen(FS_TOKEN_START_STR))) {
			*save_e_ptr = save_e;
			strfree(reparse_data);
			return (EINVAL);
		}

		/* skip over FS_TOKEN_START_STR */
		s_str += strlen(FS_TOKEN_START_STR);

		/* locate FS_TOKEN_END_STR */
		if ((cp = strstr(s_str, FS_TOKEN_END_STR)) == NULL) {
			*save_e_ptr = save_e;
			strfree(reparse_data);
			return (EINVAL);
		}

		tcnt++;
		save_c = *cp;
		*cp = '\0';

		/* check for valid characters in service type */
		if (reparse_validate_svctype(s_str) == B_FALSE) {
			*cp = save_c;
			*save_e_ptr = save_e;
			strfree(reparse_data);
			return (EINVAL);
		}

		if (strlen(s_str) == 0) {
			*cp = save_c;
			*save_e_ptr = save_e;
			strfree(reparse_data);
			return (EINVAL);
		}

		if (reparse_validate_svc_token(s_str) == B_FALSE) {
			*cp = save_c;
			*save_e_ptr = save_e;
			strfree(reparse_data);
			return (EINVAL);
		}

		/* create a nvpair entry */
		if (nvl != NULL &&
		    (err = reparse_add_nvpair(s_str, nvl)) != 0) {
			*cp = save_c;
			*save_e_ptr = save_e;
			strfree(reparse_data);
			return (err);
		}

		*cp = save_c;

		/* skip over FS_TOKEN_END_STR */
		cp += strlen(FS_TOKEN_END_STR);
		cp = reparse_skipspace(cp);
		s_str = cp;
	}
	*save_e_ptr = save_e;
	strfree(reparse_data);

	return (tcnt ? 0 : EINVAL);
}

static int
reparse_add_nvpair(char *token, nvlist_t *nvl)
{
	int err;
	char save_c, *cp;

	if ((cp = strchr(token, ':')) == NULL)
		return (EINVAL);

	save_c = *cp;
	*cp = '\0';
	err = nvlist_add_string(nvl, token, cp + 1);
	*cp = save_c;

	return (err);
}

static int
reparse_create_nvlist(const char *string, nvlist_t *nvl)
{
	if (nvl == NULL)
		return (EINVAL);

	return (reparse_validate_create_nvlist(string, nvl));
}
