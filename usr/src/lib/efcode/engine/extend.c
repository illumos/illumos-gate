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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/shm.h>
#include <dlfcn.h>
#include <fcode/private.h>

static void
do_dlopen(fcode_env_t *env)
{
	char *name;
	int mode;
	void *pl;

	mode = POP(DS);
	name = pop_a_string(env, NULL);
	pl = dlopen(name, mode);
	PUSH(DS, (fstack_t)pl);
}

static void
do_extend(fcode_env_t *env)
{
	parse_word(env);
	PUSH(DS, (fstack_t)RTLD_NOW);
	do_dlopen(env);
	drop(env);
}

static void
do_dlclose(fcode_env_t *env)
{
	void *pl = (void *)POP(DS);
	dlclose(pl);
}

static void
do_dlsym(fcode_env_t *env)
{
	char *name;
	fstack_t d;

	name = pop_a_string(env, NULL);
	d = POP(DS);
	d = (fstack_t)dlsym((void *) d, name);
	PUSH(DS, d);
}

static void
do_dlexec(fcode_env_t *env)
{
	int args;
	fstack_t a, b, c, d;
	fstack_t (*fn0)(void);
	fstack_t (*fn1)(fstack_t);
	fstack_t (*fn2)(fstack_t, fstack_t);
	fstack_t (*fn3)(fstack_t, fstack_t, fstack_t);
	fstack_t (*fn4)(fstack_t, fstack_t, fstack_t, fstack_t);

	args = POP(DS);
	a = POP(DS);
	switch (args) {

	case 0:
		fn0 = (fstack_t (*)(void)) a;
		a = fn0();
		PUSH(DS, a);
		break;

	case 1:
		fn1 = (fstack_t (*)(fstack_t)) a;
		a = POP(DS);
		a = fn1(a);
		PUSH(DS, a);
		break;

	case 2:
		fn2 = (fstack_t (*)(fstack_t, fstack_t))a;
		a = POP(DS);
		b = POP(DS);
		a = fn2(a, b);
		PUSH(DS, a);
		break;

	case 3:
		fn3 = (fstack_t (*)(fstack_t, fstack_t, fstack_t))a;
		a = POP(DS);
		b = POP(DS);
		c = POP(DS);
		a = fn3(a, b, c);
		PUSH(DS, a);
		break;

	case 4:
		fn4 = (fstack_t (*)(fstack_t, fstack_t, fstack_t, fstack_t))a;
		a = POP(DS);
		b = POP(DS);
		c = POP(DS);
		d = POP(DS);
		a = fn4(a, b, c, d);
		PUSH(DS, a);
		break;
	}
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,		"dl-open",	do_dlopen);
	FORTH(0,		"dl-close",	do_dlclose);
	FORTH(0,		"dl-sym",	do_dlsym);
	FORTH(0,		"dl-exec",	do_dlexec);
	FORTH(IMMEDIATE,	"extend-from",	do_extend);
}
