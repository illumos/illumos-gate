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
#include <exec_attr.h>
#include "getent.h"

static int
putexecattr(const execattr_t *exec, FILE *fp)
{
	int i;
	kva_t *attrs;
	kv_t *data;

	if (exec == NULL)
		return (1);

	if (fprintf(fp, "%s:%s:%s:%s:%s:%s:",
	    exec->name != NULL ? exec->name : "",
	    exec->policy != NULL ? exec->policy : "",
	    exec->type != NULL ? exec->type : "",
	    exec->res1 != NULL ? exec->res1 : "",
	    exec->res2 != NULL ? exec->res2 : "",
	    exec->id != NULL ? exec->id : "") == EOF)
		return (1);
	attrs = exec->attr;
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
dogetexecattr(const char **list)
{
	execattr_t *pexec;
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL) {
		setexecattr();
		while ((pexec = getexecattr()) != NULL)
			(void) putexecattr(pexec, stdout);
		endexecattr();
	} else {
		for (; *list != NULL; list++) {
			pexec = getexecprof(*list, NULL, NULL, GET_ALL);
			if (pexec == NULL) {
				rc = EXC_NAME_NOT_FOUND;
			} else {
				for (; pexec != NULL; pexec = pexec->next) {
					(void) putexecattr(pexec, stdout);
				}

			}
		}
	}

	return (rc);
}
