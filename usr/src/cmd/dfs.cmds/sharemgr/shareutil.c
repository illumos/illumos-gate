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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "sharemgr.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Utility functions shared by sharemgr and sharectl.
 */

/*
 * add_opt(optlist, optarg, security?)
 *	Add a new parsed option to the option list provided.
 *	If the option is a security option, only add if we are
 *	processing security options.
 */
int
add_opt(struct options **optlistp, char *optarg, int unset)
{
	struct options *newopt, *tmp, *optlist;

	optlist = *optlistp;
	newopt = (struct options *)malloc(sizeof (struct options));
	if (newopt != NULL) {
		char *optname;
		char *optvalue;

		/* extract property/value pair */
		optname = optarg;
		if (!unset) {
		    optvalue = strchr(optname, '=');
		    if (optvalue == NULL) {
			free(newopt);
			return (OPT_ADD_SYNTAX);
		    }
		    *optvalue++ = '\0'; /* separate the halves */
		} else {
		    optvalue = NULL;
		}

		newopt->optname = optname;
		newopt->optvalue = optvalue;
		newopt->next = NULL;
		if (optlist == NULL) {
			optlist = newopt;
		} else {
			for (tmp = optlist; tmp->next != NULL;
			    tmp = tmp->next) {
			}
			tmp->next = newopt;
		}
		*optlistp = optlist;
		return (OPT_ADD_OK);
	}
	return (OPT_ADD_MEMORY);
}
