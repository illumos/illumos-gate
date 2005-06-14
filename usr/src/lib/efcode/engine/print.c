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

#define	DIGIT(x)	(((x) > 9) ? ((x) + 'a' - 10) : ((x) + '0'))

void
to_digit(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, ">digit");
	TOS = DIGIT(TOS);
}

void
pic_hold(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "hold");
	*(--env->picturebufpos) = (char) POP(DS);
}

void
pic_start(fcode_env_t *env)
{
	env->picturebufpos = env->picturebuf + env->picturebuflen - 1;
	*env->picturebufpos = 0;
}

void
pic_ustop(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "u#>");
	(void) POP(DS);
	push_string(env, env->picturebufpos, strlen(env->picturebufpos));
}

void
pic_unsigned(fcode_env_t *env)
{
	ufstack_t a, b;

	CHECK_DEPTH(env, 1, "u#");
	a = (ufstack_t) TOS;
	b = a % env->num_base;
	TOS = (fstack_t) (a / env->num_base);
	*(--env->picturebufpos) = DIGIT(b);
}

void
pic_sign(fcode_env_t *env)
{
	fstack_t s;

	CHECK_DEPTH(env, 1, "sign");
	s = POP(DS);
	if (s < 0) {
		PUSH(DS, '-');
		pic_hold(env);
	}
}

static void
pic_uremainder(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "u#s");
	do {
		pic_unsigned(env);
	} while (TOS);
}

void
format_number(fcode_env_t *env, int neg, int width)
{
	pic_start(env);
	if (width == 0) {
		PUSH(DS, ' ');
		pic_hold(env);
	}
	pic_uremainder(env);
	if (env->num_base == 10 && neg) {
		PUSH(DS, '-');
		pic_hold(env);
	}
	width -= strlen(env->picturebufpos);
	while (width > 0) {
		PUSH(DS, ' ');
		pic_hold(env);
		width--;
	}
	pic_ustop(env);
}

static void
convert_num(fcode_env_t *env)
{
	int n;

	CHECK_DEPTH(env, 1, "(.)");
	n = 0;
	if (env->num_base == 10 && TOS < 0) {
		TOS = -TOS;
		n = 1;
	}
	format_number(env, n, 0);
}

void
do_dot_r(fcode_env_t *env)
{
	int w, n;

	CHECK_DEPTH(env, 2, ".r");
	n = 0;
	w = (int) POP(DS);
	if (env->num_base == 10 && TOS < 0) {
		TOS = -TOS;
		n = 1;
	}
	format_number(env, n, w);
	type(env);
}

void
do_udot_r(fcode_env_t *env)
{
	int w;

	CHECK_DEPTH(env, 2, "u.r");
	w = (int) POP(DS);
	format_number(env, 0, w);
	type(env);
}

void
do_dot(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, ".");
	PUSH(DS, 0);
	do_dot_r(env);
}

void
do_dot_d(fcode_env_t *env)
{
	int base;

	CHECK_DEPTH(env, 1, ".d");
	base = env->num_base;
	env->num_base = 10;
	do_dot(env);
	env->num_base = base;
}

void
do_dot_x(fcode_env_t *env)
{
	int base;

	CHECK_DEPTH(env, 1, ".x");
	base = env->num_base;
	env->num_base = 16;
	do_dot(env);
	env->num_base = base;
}

void
do_udot(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "u.");
	PUSH(DS, 0);
	do_udot_r(env);
}

void
pic_dunsigned(fcode_env_t *env)
{
	ufstack_t b;
	u_dforth_t a;

	CHECK_DEPTH(env, 2, "#");
	a = pop_double(env);
	b = a % env->num_base;
	a /= env->num_base;
	push_double(env, a);
	*(--env->picturebufpos) = DIGIT(b);
}

void
pic_dremainder(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "#s");
	do {
		pic_dunsigned(env);
	} while (peek_double(env));
}

void
pic_dstop(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "#>");
	(void) pop_double(env);
	push_string(env, env->picturebufpos, strlen(env->picturebufpos));
}


#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;
	ASSERT(env);
	NOTICE;

	env->picturebuflen = 0x100;
	env->picturebuf = MALLOC(env->picturebuflen);

	ANSI(0x095, 0,		"hold",			pic_hold);
	ANSI(0x096, 0,		"<#",			pic_start);
	ANSI(0x097, 0,		"u#>",			pic_ustop);
	ANSI(0x098, 0,		"sign",			pic_sign);
	ANSI(0x099, 0,		"u#",			pic_unsigned);
	ANSI(0x09a, 0,		"u#s",			pic_uremainder);
	ANSI(0x09b, 0,		"u.",			do_udot);
	P1275(0x09c, 0,		"u.r",			do_udot_r);
	P1275(0x09d, 0,		".",			do_dot);
	ANSI(0x09e, 0,		".r",			do_dot_r);

	ANSI(0x0c7, 0,		"#", 			pic_dunsigned);
	ANSI(0x0c8, 0,		"#s",			pic_dremainder);
	ANSI(0x0c9, 0,		"#>",			pic_dstop);

	FORTH(0,		">digit",		to_digit);
	FORTH(0,		"(.)",			convert_num);
	FORTH(0,		".d",			do_dot_d);
	FORTH(0,		".x",			do_dot_x);
}
