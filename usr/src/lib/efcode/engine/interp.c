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
#include <fcode/log.h>

void
do_run(fcode_env_t *env, int next)
{
	token_t target, indirect;
	void (*fn)(fcode_env_t *env);
	int debug_state = current_debug_state(env);
	extern void do_memory_watch(fcode_env_t *env);

	for (; ; ) {
		if (next) {
			DEBUGF(NEXT_VITALS, output_vitals(env);
			    log_message(MSG_FC_DEBUG, "\n"));
			CHECK_INTERRUPT;
			if (IP == NULL)
				break;
			WA = (token_t *) *IP;
			IP++;
		}
		check_for_debug_entry(env);
		indirect = *WA;
		if (indirect & 1) {
			target = indirect & ~1;
			target = *((token_t *)target);
		} else
			target = indirect;
		fn = (void (*)(fcode_env_t *)) target;
		if (do_exec_debug(env, (void *)fn))
			break;
		if (indirect & 1) {
			PUSH(DS, (fstack_t) (WA+1));
			WA = (token_t *) target;
		}
		WA++;
		fn(env);
		check_vitals(env);
		check_for_debug_exit(env);
		do_memory_watch(env);
		next = 1;
	}
	clear_debug_state(env, debug_state);
}

void
do_semi(fcode_env_t *env)
{
	CHECK_RETURN_DEPTH(env, 1, ";");
	check_semi_debug_exit(env);
	IP = (token_t *) POP(RS);
}

void
do_colon(fcode_env_t *env)
{
	PUSH(RS, (fstack_t) IP);
	IP = WA;
}

void
do_alias(fcode_env_t *env)
{
	token_t *ip;

	ip = IP;
	IP = 0;
	WA = (token_t *) *WA;
	do_run(env, 0);
	IP = ip;
}

void
execute(fcode_env_t *env)
{
	token_t *ip, *wa;

	/*
	 * In order to ensure that only this token executes we
	 * force IP to zero after stashing it, then when the stack
	 * unwinds (do_run returns) we can restore the old value.
	 */
	CHECK_DEPTH(env, 1, "execute");
	ip = IP;
	wa = WA;
	IP = 0;
	WA = (token_t *) POP(DS);
	do_run(env, 0);
	IP = ip;
	WA = wa;
}
