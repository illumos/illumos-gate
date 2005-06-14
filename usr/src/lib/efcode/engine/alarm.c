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
#include <signal.h>
#include <unistd.h>
#include <fcode/private.h>

/*
 * 'user-abort' Fcode
 */
void
user_abort(fcode_env_t *env)
{
	forth_abort(env, "user-abort called");
}

static fstack_t alarm_xt;
static fstack_t alarm_ms;
static fcode_env_t *alarm_env;

static void
catch_alarm(int signo)
{
	fcode_env_t *env = alarm_env;

	if (env && alarm_xt && alarm_ms) {
		PUSH(DS, alarm_xt);
		execute(env);
		signal(SIGALRM, catch_alarm);
		alarm((alarm_ms + 999)/1000);
	}
}

/*
 * 'alarm' Fcode
 */
void
do_alarm(fcode_env_t *env)
{
	fstack_t ms, xt;

	CHECK_DEPTH(env, 2, "alarm");
	ms = POP(DS);
	xt = POP(DS);
	if (ms == 0) {
		alarm(0);
		signal(SIGALRM, SIG_DFL);
		alarm_xt = 0;
		alarm_ms = 0;
		alarm_env = 0;
	} else {
		signal(SIGALRM, catch_alarm);
		alarm_xt = xt;
		alarm_ms = ms;
		alarm_env = env;
		alarm((ms + 999)/1000);
	}
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	P1275(0x213, 0,		"alarm",		do_alarm);

	P1275(0x219, 0,		"user-abort",		user_abort);
}
