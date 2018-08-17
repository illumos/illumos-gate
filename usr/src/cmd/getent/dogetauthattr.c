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
 * Copyright (c) 2018 Peter Tribble.
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <auth_attr.h>
#include "getent.h"

static int
putauthattr(const authattr_t *auth, FILE *fp)
{
	int i;
	kva_t *attrs;
	kv_t *data;

	if (auth == NULL)
		return (1);

	if (fprintf(fp, "%s:%s:%s:%s:%s:",
	    auth->name != NULL ? auth->name : "",
	    auth->res1 != NULL ? auth->res1 : "",
	    auth->res2 != NULL ? auth->res2 : "",
	    auth->short_desc != NULL ? auth->short_desc : "",
	    auth->long_desc != NULL ? auth->long_desc : "") == EOF)
		return (1);
	attrs = auth->attr;
	if (attrs != NULL) {
		data = attrs->data;
		for (i = 0; i < attrs->length; i++) {
			if (fprintf(fp, "%s=%s%s",
			    data[i].key != NULL ? data[i].key : "",
			    data[i].value != NULL ? data[i].value : "",
			    i < (attrs->length)-1 ? ";" : "") == EOF)
				return (1);
		}
	}
	if (putc('\n', fp) == EOF)
		return (1);
	return (0);
}

int
dogetauthattr(const char **list)
{
	authattr_t *pauth;
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL) {
		setauthattr();
		while ((pauth = getauthattr()) != NULL)
			(void) putauthattr(pauth, stdout);
		endauthattr();
	} else {
		for (; *list != NULL; list++) {
			pauth = getauthnam(*list);
			if (pauth == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putauthattr(pauth, stdout);
		}
	}

	return (rc);
}
