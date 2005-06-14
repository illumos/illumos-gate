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
#include <string.h>

#include <fcode/private.h>
#include <fcode/log.h>

#define	NUM_DEFAULT_ACTIONS	7

/*
 * value_fetch and value_store are the same as "fetch" and "store", but
 * we'll leave them implemented here for now.
 */
static void
value_fetch(fcode_env_t *env)
{
	variable_t *addr;

	CHECK_DEPTH(env, 1, "value_fetch");
	addr = (variable_t *)POP(DS);
	PUSH(DS, (variable_t)*addr);
}

static void
value_store(fcode_env_t *env)
{
	variable_t *addr;

	CHECK_DEPTH(env, 1, "value_store");
	addr = (variable_t *)POP(DS);
	*addr = (variable_t)POP(DS);
}

void *
get_internal_address(fcode_env_t *env)
{
	int *ptr;

	CHECK_DEPTH(env, 1, "get_internal_address");
	ptr = (int *)POP(DS);
	if (*ptr > 0)
		return ((uchar_t *)env + *ptr);
	return ((uchar_t *)MYSELF - *ptr);
}

void
internal_env_fetch(fcode_env_t *env)
{
	instance_t **iptr;

	CHECK_DEPTH(env, 1, "internal_env_fetch");
	iptr = (instance_t **)get_internal_address(env);
	PUSH(DS, (fstack_t)(*iptr));
}

void
internal_env_store(fcode_env_t *env)
{
	instance_t **iptr;

	CHECK_DEPTH(env, 2, "internal_env_store");
	iptr = (instance_t **)get_internal_address(env);
	*iptr = (instance_t *)POP(DS);
}

void
internal_env_addr(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 1, "internal_env_addr");
	d = (fstack_t)get_internal_address(env);
	PUSH(DS, d);
}

void
do_buffer_data(fcode_env_t *env, token_t *d, int instance)
{
	if (!*d) {	/* check if buffer not alloc'ed yet */
		token_t *buf;

		if (instance) {
			int n, off;

			n = TOKEN_ROUNDUP(d[1]);
			buf = alloc_instance_data(env, UINIT_DATA, n, &off);
			memset(buf, 0, d[1]);
		} else {
			buf = (token_t *)HERE;
			set_here(env, HERE + d[1], "do_buffer_data");
		}
		*d = (token_t)buf;
	}
	PUSH(DS, *d);
}

void
ibuffer_init(fcode_env_t *env)
{
	token_t *d;

	d = get_instance_address(env);
	do_buffer_data(env, d, 1);
}

void
buffer_init(fcode_env_t *env)
{
	token_t *d;

	CHECK_DEPTH(env, 1, "buffer_init");
	d = (token_t *)POP(DS);
	do_buffer_data(env, d, 0);
}

void
do_defer(fcode_env_t *env)
{
	fetch(env);
	execute(env);
}

token_t *value_actions[NUM_DEFAULT_ACTIONS];
token_t value_defines[NUM_DEFAULT_ACTIONS][3] = {
	{ (token_t)&value_fetch, (token_t)&value_store, (token_t)&noop },
	{ (token_t)&fetch_instance_data, (token_t)&set_instance_data,
	    (token_t)&address_instance_data },
	{ (token_t)&internal_env_fetch, (token_t)&internal_env_store,
	    (token_t)&internal_env_addr },
	{ (token_t)&do_defer, (token_t)&store, (token_t)&noop },
	{ (token_t)&idefer_exec, (token_t)&set_instance_data,
	    (token_t)&address_instance_data },
	{ (token_t)&buffer_init, (token_t)&two_drop, (token_t)&noop, },
	{ (token_t)&ibuffer_init, (token_t)&two_drop,
	    (token_t)&address_instance_data }
};

int
run_action(fcode_env_t *env, acf_t acf, int action)
{
	token_t *p = (token_t *)acf;

	if ((p[0] & 1) == 0) {
		log_message(MSG_WARN, "run_action: acf: %p @acf: %p not"
		    " indirect\n", acf, p[0]);
		return (1);
	}

	p = (token_t *)(p[0] & ~1);

	if (action >= p[1] || action < 0) {
		log_message(MSG_WARN, "run_action: acf: %p action: %d"
		    " out of range: 0-%d\n", acf, action, (int)p[1]);
		return (1);
	}

	if (p[0] == (token_t)&do_default_action) {
		fstack_t d;

		d = (fstack_t)p[action+2];
		PUSH(DS, d);
		execute(env);
		return (0);
	}
	log_message(MSG_WARN, "run_action: acf: %p/%p not default action\n",
	    acf, p[0]);
	return (1);
}

void
do_default_action(fcode_env_t *env)
{
	acf_t a;

	CHECK_DEPTH(env, 1, "do_default_action");
	a = (acf_t)TOS;
	(void) run_action(env, (a-1), 0);
}

void
do_set_action(fcode_env_t *env)
{
	acf_t  a = (acf_t)TOS;

	CHECK_DEPTH(env, 1, "do_set_action");
	TOS += sizeof (acf_t);
	(void) run_action(env, a, 1);
}

void
action_colon(fcode_env_t *env)
{
	token_roundup(env, "action_colon");
	env->action_ptr[env->action_count] = (token_t)HERE;
	COMPILE_TOKEN(&do_colon);
	env->action_count++;
	env->state |= 1;
}

void
actions(fcode_env_t *env)
{
	int n;
	token_t *d;

	token_roundup(env, "actions");
	d = (token_t *)HERE;
	*d++ = (token_t)&do_default_action;
	n = (int)POP(DS);
	*d++ = n;
	env->num_actions = n;
	env->action_count = 0;
	env->action_ptr = d;
	d += n;
	set_here(env, (uchar_t *)d, "actions");
}

void
install_actions(fcode_env_t *env, token_t *table)
{
	acf_t *dptr;
	token_t p;

	dptr  = (acf_t *)LINK_TO_ACF(env->lastlink);
	p = (token_t)table;
	p -= (sizeof (token_t) + sizeof (acf_t));
	*dptr = (acf_t)(p | 1);
}

void
use_actions(fcode_env_t *env)
{
	if (env->state) {
		TODO;	/* use-actions in compile state. */
	} else {
		install_actions(env, env->action_ptr);
	}
}

void
perform_action(fcode_env_t *env)
{
	int n;
	acf_t a;

	CHECK_DEPTH(env, 2, "perform_action");
	n = POP(DS);
	a = (acf_t)POP(DS);
	PUSH(DS, (fstack_t)ACF_TO_BODY(a));

	if (run_action(env, a, n)) {
		system_message(env, "Bad Object action");
	}
}

void
define_actions(fcode_env_t *env, int n, token_t *array)
{
	int a;

	PUSH(DS, (fstack_t)n);
	actions(env);

	a = 0;
	while (n--) {
		action_colon(env);
		COMPILE_TOKEN(&array[a]);
		env->state |= 8;
		semi(env);
		a++;
	}
}

/*
 * This is for things like my-self which have meaning to the
 * forth engine but I don't want to turn them into standard forth values
 * that would make the 'C' variables hard to understand, instead these
 * 'global' state variables will act directly upon the native 'C' structures.
 */

void
set_internal_value_actions(fcode_env_t *env)
{
	ASSERT(value_actions[2]);
	install_actions(env, value_actions[2]);
}

void
set_value_actions(fcode_env_t *env, int which)
{
	ASSERT((which == 0) || (which == 1));
	ASSERT(value_actions[which]);
	install_actions(env, value_actions[which]);
}

void
set_defer_actions(fcode_env_t *env, int which)
{
	ASSERT((which == 0) || (which == 1));
	ASSERT(value_actions[which+3]);
	install_actions(env, value_actions[which+3]);
}

void
set_buffer_actions(fcode_env_t *env, int which)
{
	ASSERT((which == 0) || (which == 1));
	ASSERT(value_actions[which+5]);
	install_actions(env, value_actions[which+5]);
}

#if defined(DEBUG)

void
do_get(fcode_env_t *env)
{
	PUSH(DS, 0);
	perform_action(env);
}

void
do_set(fcode_env_t *env)
{
	PUSH(DS, 1);
	perform_action(env);
}

void
do_addr(fcode_env_t *env)
{
	PUSH(DS, 2);
	perform_action(env);
}

void
dump_actions(fcode_env_t *env)
{
	int i;
	for (i = 0; i < NUM_DEFAULT_ACTIONS; i++) {
		log_message(MSG_INFO, "Action Set: %d = %p\n", i,
		    value_actions[i]);
	}
}
#endif	/* DEBUG */

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;
	int i;

	ASSERT(env);
	NOTICE;

	for (i = 0; i < NUM_DEFAULT_ACTIONS; i++) {
		define_actions(env, 3, value_defines[i]);
		value_actions[i] = env->action_ptr;
	}

#if defined(DEBUG)
	FORTH(0,		"get",			do_get);
	FORTH(0,		"set",			do_set);
	FORTH(0,		"addr",			do_addr);
	FORTH(0,		"dump-actions",		dump_actions);
	FORTH(IMMEDIATE,	"actions",		actions);
	FORTH(IMMEDIATE,	"use-actions",		use_actions);
	FORTH(IMMEDIATE,	"action:",		action_colon);
	FORTH(0,		"perform-action",	perform_action);
#endif /* DEBUG */
}
