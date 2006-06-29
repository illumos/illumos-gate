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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/param.h>
#include <memory.h>
#include <config_admin.h>
#include "mema_test.h"

void *
mtest_allocate_buf(
	mtest_handle_t handle,
	size_t size)
{
	struct mtest_alloc_ent *new_ent;

	new_ent =
	    (struct mtest_alloc_ent *)malloc(sizeof (struct mtest_alloc_ent));
	if (new_ent == NULL)
		return (NULL);

	new_ent->buf = malloc(size);
	if (new_ent->buf == NULL) {
		free((void *)new_ent);
		return (NULL);
	}
	/* TODO: probably not thread safe? */
	new_ent->next = handle->alloc_list;
	handle->alloc_list = new_ent;

	return (new_ent->buf);
}

/* This routine dedicated to George Cameron */
void
mtest_deallocate_buf(
	mtest_handle_t handle,
	void *buf)
{
	struct mtest_alloc_ent **p, *p1;

	p = &handle->alloc_list;
	while ((*p) != NULL && (*p)->buf != buf)
		p = &(*p)->next;
	assert((*p) != NULL);
	p1 = *p;
	*p = (*p)->next;
	free(p1->buf);
	free((void *)p1);
}

void
mtest_deallocate_buf_all(mtest_handle_t handle)
{
	struct mtest_alloc_ent *p1;

	while ((p1 = handle->alloc_list) != NULL) {
		handle->alloc_list = p1->next;
		free(p1->buf);
		free((void *)p1);
	}
}

void
mtest_message(mtest_handle_t handle, const char *msg)
{
	if (handle->msgp != NULL && handle->msgp->message_routine != NULL) {
		(*handle->msgp->message_routine)(handle->msgp->appdata_ptr,
		    msg);
	}
}
