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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <libintl.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include "ns_sldap.h"
#include "ns_internal.h"

/*
 * getldaplaliasbyname() retrieves the aliases information from the LDAP server.
 * This is requires that the LDAP naming information (ie. LDAP_CLIENT_CACHE
 * file) is configured properly on the client machine.
 *
 * Return value:
 *      0 = success;
 *      1 = alias not found;
 *      -1 = other failure.  Contents in answer are undefined.
 */

#define	ALIAS_FILTER	 "(&(objectclass=mailgroup)(|(cn=%s)(mail=%s)))"
#define	ALIAS_FILTER_SSD "(&(%%s)(|(cn=%s)(mail=%s)))"
#define	MAIL_CN		"cn"
#define	MAIL_ATTRIBUTE	"mail"
#define	MAIL_MEMBER	"mgrpRFC822MailMember"

/*
 * This is a generic filter call back function for
 * merging the filter from service search descriptor with
 * an existing search filter. This routine expects userdata
 * contain a format string with a single %s in it, and will
 * use the format string with sprintf() to insert the SSD filter.
 *
 * This routine is passed to the __ns_ldap_list() API as the
 * filter call back together with filter and userdata. For example,
 * "(&(objectclass=mailgroup)(|(cn=abc)(mail=abc)))" as filter
 * and "(&(%s)(|(cn=abc)(mail=abc)))" as userdata.
 * This routine will then be called by __ns_ldap_list() to output
 * "(&(dept=sds)(|(cn=abc)(mail=abc)))" as the real search
 * filter, if the input SSD contains a filter "dpet=sds".
 */
int
__s_api_merge_SSD_filter(const ns_ldap_search_desc_t *desc,
			char **realfilter,
			const void *userdata)
{
	int	len;

	/* sanity check */
	if (realfilter == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*realfilter = NULL;

	if (desc == NULL || desc->filter == NULL ||
			userdata == NULL)
		return (NS_LDAP_INVALID_PARAM);

	len = strlen(userdata) + strlen(desc->filter) + 1;

	*realfilter = (char *)malloc(len);
	if (*realfilter == NULL)
		return (NS_LDAP_MEMORY);

	(void) sprintf(*realfilter, (char *)userdata,
			desc->filter);

	return (NS_LDAP_SUCCESS);
}
int
__getldapaliasbyname(char *alias, char *answer, size_t ans_len)
{
	char		*service = "aliases";
	char		filter[BUFSIZE];
	char		userdata[BUFSIZE];
	char		*attribute[2];
	ns_ldap_result_t	*result = NULL;
	ns_ldap_error_t	*errorp = NULL;
	int		rc, i, j, len, comma;
	ns_ldap_entry_t	*entry = NULL;
	char		**attr_value = NULL;

	if (!alias || !*alias || !answer || ans_len == 0) {
		errno = EINVAL;
		return (-1);
	}

	answer[0] = '\0';

	/* get the aliases */
	if (snprintf(filter, sizeof (filter), ALIAS_FILTER, alias, alias) < 0) {
		errno = EINVAL;
		return (-1);
	}

	/* get the userdata for __ns_ldap_list filter call back */
	if (snprintf(userdata, sizeof (userdata), ALIAS_FILTER_SSD,
	    alias, alias) < 0) {
		errno = EINVAL;
		return (-1);
	}

	attribute[0] = MAIL_MEMBER;
	attribute[1] = NULL;

	/* should we do hardlookup */
	rc = __ns_ldap_list(service, (const char *)filter,
		__s_api_merge_SSD_filter,
		(const char **)attribute, NULL, 0, &result,
		&errorp, NULL, userdata);

	if (rc == NS_LDAP_NOTFOUND) {
		errno = ENOENT;
		return (1);
	} else if (rc != NS_LDAP_SUCCESS) {
#ifdef DEBUG
		char *p;
		(void) __ns_ldap_err2str(rc, &p);
		if (errorp) {
			if (errorp->message)
				(void) fprintf(stderr, "%s (%s)\n", p,
					errorp->message);
		} else
			(void) fprintf(stderr, "%s\n", p);
#endif /* DEBUG */
		(void) __ns_ldap_freeError(&errorp);
		return (-1);
	}

	/* build the return value */
	answer[0] = '\0';
	len = 0;
	comma = 0;
	entry = result->entry;
	for (i = 0; i < result->entries_count; i++) {
		attr_value = __ns_ldap_getAttr(entry, MAIL_MEMBER);
		if (attr_value == NULL) {
			errno = ENOENT;
			return (-1);
		}
		for (j = 0; attr_value[j]; j++) {
			char	*tmp, *newhead;

			tmp = attr_value[j];
			while (*tmp == ' ' || *tmp == '\t' && *tmp != '\0')
				tmp++;
			newhead = tmp;
			while (*tmp != '\0') tmp++;
			while (*tmp == ' ' || *tmp == '\t' || *tmp == '\0' &&
			    tmp != newhead) {
				*tmp-- = '\0';
			}
			len = len + comma + strlen(newhead);
			if ((len + 1) > ans_len) {
				(void) __ns_ldap_freeResult(&result);
				errno = EOVERFLOW;
				return (-1);
			}
			if (comma)
				(void) strcat(answer, ",");
			else
				comma = 1;
			(void) strcat(answer, newhead);
		}
	}

	(void) __ns_ldap_freeResult(&result);
	errno = 0;
	return (0);
}
