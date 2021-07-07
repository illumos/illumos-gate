/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2021 Planets Communications B.V.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include "getent.h"

int
dogetnetgr(const char **list)
{
	uint_t cnt;
	char *host, *user, *dom;
	const char *host_filter, *user_filter, *dom_filter;
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL)
		return (EXC_ENUM_NOT_SUPPORTED);

	/*
	 * Count the arguments given.
	 */
	cnt = 0;
	while (list[cnt] != NULL)
		cnt++;

	switch (cnt) {
	case 1:
		if (setnetgrent(list[0]) != 0)
			return (EXC_ERROR);
		printf("%s", list[0]);
		while (getnetgrent(&host, &user, &dom) != 0) {
			printf(" (%s,%s,%s)",
			    (host) ? host : "",
			    (user) ? user : "",
			    (dom)  ? dom  : "");
		}
		printf("\n");
		break;
	case 4:
		host_filter = (strcmp(list[1], "*") == 0) ? NULL : list[1];
		user_filter = (strcmp(list[2], "*") == 0) ? NULL : list[2];
		dom_filter = (strcmp(list[3], "*") == 0) ? NULL : list[3];
		printf("%-21s (%s,%s,%s) = %d\n", list[0],
		    (host_filter) ? host_filter : "",
		    (user_filter) ? user_filter : "",
		    (dom_filter)  ? dom_filter  : "",
		    innetgr(list[0], host_filter, user_filter, dom_filter));
		break;
	default:
		rc = EXC_SYNTAX;
		break;
	}

	return (rc);
}
