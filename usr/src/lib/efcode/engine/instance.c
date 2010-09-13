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

#include <fcode/private.h>

/*
 * Return a pointer to the allocated instance data.
 * If the data was initialised then return a pointer to the initialisation
 * buffer otherwise return a pointer to the un-init data.
 */
token_t *
alloc_instance_data(fcode_env_t *env, int init, int n, int *offset)
{
	int ptr;

	*offset = ptr = MYSELF->device->data_size[init];
	MYSELF->device->data_size[init] += n;
	if (init == INIT_DATA)
		return (&MYSELF->device->init_data[ptr]);
	else
		return (&MYSELF->data[init][ptr]);
}

token_t *
get_instance_address(fcode_env_t *env)
{
	int which;
	token_t *ptr;
	token_t offset;

	CHECK_DEPTH(env, 1, "get_instance_address");
	ptr = (token_t *) POP(DS);
	offset = *ptr;
	if (offset < 0) {
		offset = -offset;
		which = UINIT_DATA;
	} else {
		which = INIT_DATA;
	}
	return (&MYSELF->data[which][offset]);
}

void
fetch_instance_data(fcode_env_t *env)
{
	token_t *ptr;

	CHECK_DEPTH(env, 1, "get_instance_data");
	ptr = get_instance_address(env);
	PUSH(DS, *ptr);
}

void
set_instance_data(fcode_env_t *env)
{
	token_t *ptr;

	CHECK_DEPTH(env, 2, "set_instance_data");
	ptr = get_instance_address(env);
	*ptr = POP(DS);
}

void
address_instance_data(fcode_env_t *env)
{
	token_t *ptr;

	CHECK_DEPTH(env, 1, "address_instance_data");
	ptr = get_instance_address(env);
	PUSH(DS, (fstack_t) ptr);
}

void
instance_variable(fcode_env_t *env)
{
	token_t *ptr;

	PUSH(DS, (fstack_t) WA);
	ptr = get_instance_address(env);
	PUSH(DS, (fstack_t) ptr);
}

void
idefer_exec(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "idefer_exec");
	fetch_instance_data(env);
	execute(env);
}
