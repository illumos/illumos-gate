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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <errno.h>
#include <malloc.h>
#include <mdesc.h>
#include <pri.h>
#include "priplugin.h"

static void pri_free(void *bufp, size_t size);
static uint64_t *md_bufp = NULL;
static uint64_t *new_md_bufp;

int
pri_devinit(uint64_t *tok)
{
	int status;

	new_md_bufp = NULL;
	status = 0;
	if (pri_get(PRI_WAITGET, tok, &new_md_bufp, malloc, pri_free) ==
	    (ssize_t)-1) {
		pri_debug(LOG_NOTICE, "pri_devinit: can'r read from "
		    "the PRI: %d\n", errno);
		status = -1;
	}
	if (new_md_bufp == NULL) {
		pri_debug(LOG_NOTICE, "pri_devinit: pri_get returned "
		    "NULL buffer!\n");
		status = -1;
	}
	return (status);
}

md_t *
pri_bufinit(md_t *mdp)
{

	if (mdp)
		md_fini(mdp);
	if (md_bufp)
		free(md_bufp);
	md_bufp = new_md_bufp;

	pri_debug(LOG_NOTICE, "pri_bufinit: done reading PRI\n");

	/*
	 * The PRI and the MD use the same data format so they can be
	 * parsed by the same functions.
	 */
	if (md_bufp) {
		mdp = md_init_intern(md_bufp, malloc, pri_free);
		if (mdp == NULL) {
			pri_debug(LOG_NOTICE, "pri_bufinit: md_init_intern "
			"failed\n");
			free(md_bufp);
			md_bufp = NULL;
		} else {
			pri_debug(LOG_NOTICE, "pri_bufinit: mdi_init_intern "
			    "completed successfully\n");
		}
	} else
		mdp = NULL;

	pri_debug(LOG_NOTICE, "pri_bufinit: returning\n");

	return (mdp);
}

/*ARGSUSED*/
static void
pri_free(void *bufp, size_t size)
{
	if (bufp)
		free(bufp);
}

void
pri_devfini(md_t *mdp)
{
	if (mdp)
		(void) md_fini(mdp);

	if (md_bufp)
		free(md_bufp);
	md_bufp = NULL;
}
