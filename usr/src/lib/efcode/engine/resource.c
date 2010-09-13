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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcode/private.h>
#include <fcode/log.h>

fc_resource_t *
find_resource(fc_resource_t **head, void *ptr, int (cmp)(void *, void *))
{
	fc_resource_t *f, *prev, *r = *head;

	f = NULL;
	prev = NULL;
	while (r) {
		if (r->data == NULL) {
			fc_resource_t *dead;

			if (prev)
				prev->next = r->next;
			else {
				*head = r->next;
			}
			dead = r;
			r = r->next;
			FREE(dead);
		} else {
			if (cmp(ptr, r->data)) {
				f = r;
				break;
			}
			prev = r;
			r = r->next;
		}
	}
	return (f);
}

void *
add_resource(fc_resource_t **head, void *ptr, int (cmp)(void *, void *))
{
	fc_resource_t *r;

	r = find_resource(head, ptr, cmp);
	if (r == NULL) {
		r = MALLOC(sizeof (fc_resource_t));
		r->data = ptr;
		r->next = *head;
		*head = r;
		return (r->data);
	}
	log_message(MSG_ERROR, "add_resource: Duplicate entry: %p\n", ptr);
	return (NULL);
}

void
free_resource(fc_resource_t **head, void *ptr,  int (cmp)(void *, void *))
{
	fc_resource_t *r;

	if ((r = find_resource(head, ptr, cmp)) != NULL)
		r->data = NULL;
	else
		log_message(MSG_ERROR, "free_resource: No such Entry: %p\n",
		    ptr);
}

#ifdef DEBUG

static int
dump_print(void *s, void *d)
{
	log_message(MSG_DEBUG, "Buffer: %p\n", d);
	return (0);
}

void
dump_resources(fcode_env_t *env)
{
	fc_resource_t **head;

	head = (fc_resource_t **) POP(DS);
	(void) find_resource(head, NULL, dump_print);
}

void
propbufs(fcode_env_t *env)
{
	PUSH(DS, (fstack_t) &env->propbufs);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	NOTICE;
	ASSERT(env);

	FORTH(0,		"propbufs",		propbufs);
	FORTH(0,		"dump-resource",	dump_resources);
}

#endif
