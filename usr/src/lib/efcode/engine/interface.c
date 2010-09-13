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
#include <stdlib.h>

#include <fcode/private.h>
#include <fcode/log.h>

/*
 * the external start point for this goo
 */

void
push_ds(fcode_env_t *env, fstack_t d)
{
	PUSH(DS, d);
}

fstack_t
pop_ds(fcode_env_t *env)
{
	return (POP(DS));
}

void
push_rs(fcode_env_t *env, fstack_t d)
{
	PUSH(RS, d);
}

fstack_t
pop_rs(fcode_env_t *env)
{
	return (POP(RS));
}

/*
 * Pushes a C string on the stack.
 */
void
push_a_string(fcode_env_t *env, char *str)
{
	if (str) {
		PUSH(DS, (fstack_t)str);
		PUSH(DS, strlen(str));
	} else {
		PUSH(DS, 0);
		PUSH(DS, 0);
	}
}

/*
 * Pops a (potentially null) string off the stack.
 */
char *
pop_a_string(fcode_env_t *env, int *lenp)
{
	int len;
	char *str;

	len = POP(DS);
	str = (char *)POP(DS);
	if (len == 0)
		str = NULL;
	else if (str == NULL)
		len = 0;
	if (lenp)
		*lenp = len;
	return (str);
}

/*
 * Pops & strdup's a string off the stack, handles NULL strings.
 */
char *
pop_a_duped_string(fcode_env_t *env, int *lenp)
{
	char *str;

	str = pop_a_string(env, lenp);
	if (str)
		return (STRDUP(str));
	return (NULL);
}

/*
 * Push Forth Double type.
 */
void
push_double(fcode_env_t *env, dforth_t d)
{
	fstack_t lo, hi;

	lo = DFORTH_LO(d);
	hi = DFORTH_HI(d);
	PUSH(DS, lo);
	PUSH(DS, hi);
}

/*
 * Pop Forth Double type.
 */
dforth_t
pop_double(fcode_env_t *env)
{
	fstack_t lo, hi;

	hi = POP(DS);
	lo = POP(DS);
	return (MAKE_DFORTH(hi, lo));
}

/*
 * Peek at top of stack Forth Double type.
 */
dforth_t
peek_double(fcode_env_t *env)
{
	dforth_t a;

	a = pop_double(env);
	push_double(env, a);
	return (a);
}

void
run_fcode(fcode_env_t *env, uchar_t *buff, int len)
{
	int i;

	/*
	 * Really just checking to see if buff is all ascii characters.
	 * Fcode normally starts with 0xfd, so for fcode, this should be
	 * a fast check.
	 */
	for (i = 0; i < len; i++)
		if (buff[i] >= 0x80)
			break;
	PUSH(DS, (fstack_t)buff);
	if (i < len) {
		/* Non-ascii found, probably Fcode */
		PUSH(DS, (fstack_t)1);
		byte_load(env);
	} else {
		/* All ascii found, probably ascii */
		PUSH(DS, len);
		fevaluate(env);
	}
}

void
run_fcode_from_file(fcode_env_t *env, char *fname, int aout_flag)
{
	uchar_t *p;
	int len;

	push_a_string(env, fname);
	load_file(env);
	len = POP(DS);
	p = (uchar_t *)POP(DS);
	if (aout_flag) {
		p += 0x20;
		len -= 0x20;
	}
	run_fcode(env, p, len);
}

fcode_env_t *
clone_environment(fcode_env_t *src, void *private)
{
	fcode_env_t *env;

	if (!src) {
		src = initial_env;
		src->private = private;
		return (src);
	}

#if 0
	src->private = private;
	if (src->my_self || src->state) {
		log_message(MSG_WARN, "Can't clone an active instance or"
		    " compile state!\n");
		return (NULL);
	}

	log_message(MSG_WARN, "Warning: Device-tree state is shared!\n");
#endif

	env = MALLOC(sizeof (fcode_env_t));
	memcpy(env, src, sizeof (fcode_env_t));

#if 0
	env->table = MALLOC((MAX_FCODE + 1) * sizeof (fcode_token));
	memcpy(env->table, src->table, (MAX_FCODE + 1) * sizeof (fcode_token));

	/*
	 * Note that cloning the dictionary doesn't make sense unless the
	 * ptrs + XT's in the dictionary are relative to BASE.
	 */
	env->base = MALLOC(dict_size);
	memcpy(env->base, src->base, dict_size);

	env->here = src->base - (uchar_t *)src + env->base;
#endif

	env->ds0 = MALLOC(stack_size * sizeof (fstack_t));
	memcpy(env->ds0, src->ds0, stack_size * sizeof (fstack_t));
	env->ds = src->ds - src->ds0 + env->ds0;

	env->rs0 = MALLOC(stack_size * sizeof (fstack_t));
	memcpy(env->rs0, src->rs0, stack_size * sizeof (fstack_t));
	env->rs = src->rs - src->rs0 + env->rs0;

	env->order = MALLOC(MAX_ORDER * sizeof (token_t));
	memcpy(env->order, src->order, MAX_ORDER * sizeof (token_t));

	env->input = MALLOC(sizeof (input_typ));

	env->catch_frame = 0;

	IP = 0;

	return (env);
}

void
destroy_environment(fcode_env_t *env)
{
	FREE(env->input);
	FREE(env->order);
	FREE(env->ds0);
	FREE(env->rs0);
#if 0
	FREE(env->base);
	FREE(env->table);
#endif
	FREE(env);

	if (env == initial_env) {
		/* This call only happens internally */

		initial_env = NULL;
		/* You had better not exercise the engine anymore! */
	}
}
