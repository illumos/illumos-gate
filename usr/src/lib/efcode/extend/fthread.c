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
#include <fcode/private.h>
#include <fcode/log.h>

static int envp;
static int envc;
static fcode_env_t *envs[4];

static void
do_clone(fcode_env_t *cenv)
{
	fcode_env_t *new;

	if (envc < 4) {
		envs[envc] = env;
		envc++;
		new = clone_environment(cenv, NULL);
		if (new) {
			envs[envc] = new;
			env = new;
			return;
		}
	}
	system_message(cenv, "clone failed");
}

static void
do_switch(fcode_env_t *cenv)
{
	int bail = 4;
	do {
		envp = (envp+1)%4;
		env = envs[envp];
		bail--;
	} while ((env == NULL) && (!bail));
	log_message(MSG_INFO, "Env: %x\n", env);
}

static void
do_release(fcode_env_t *cenv)
{
	int bail = 4;
	destroy_environment(envs[envp]);
	envs[envp] = NULL;
	do {
		envp = (envp+1)%4;
		env = envs[envp];
		bail--;
	} while ((env == NULL) && (!bail));
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	envp = 0;
	envc = 0;

	FORTH(0,	"clone",		do_clone);
	FORTH(0,	"switch",		do_switch);
	FORTH(0,	"release",		do_release);
}
