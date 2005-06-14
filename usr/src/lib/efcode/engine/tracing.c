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
#include <dlfcn.h>

#include <fcode/private.h>
#include <fcode/log.h>

#ifdef DEBUG

static void (*trace_fn)(fcode_env_t *);

void
set_tracer(fcode_env_t *env, void (*tracer)(fcode_env_t *))
{
	trace_fn = tracer;
}

void
set_level(long lvl)
{
	long debug;

	debug = get_interpreter_debug_level();
	set_interpreter_debug_level(debug | lvl);
}

void
unset_level(long lvl)
{
	long debug;

	debug = get_interpreter_debug_level();
	set_interpreter_debug_level(debug & ~lvl);
}

void
enable_trace(fcode_env_t *env)
{
	set_level(DEBUG_TRACING);
}

void
enable_stack_trace(fcode_env_t *env)
{
	set_level(DEBUG_TRACE_STACK);
}

void
disable_stack_trace(fcode_env_t *env)
{
	unset_level(DEBUG_TRACE_STACK);
}

void
disable_trace(fcode_env_t *env)
{
	unset_level(DEBUG_TRACING);
}

void
call_trace(fcode_env_t *env)
{
	set_level(DEBUG_CALL_METHOD);
}

void
no_call_trace(fcode_env_t *env)
{
	unset_level(DEBUG_CALL_METHOD);
}

void
do_fclib_trace(fcode_env_t *env, void *fn)
{
	void *address;
	Dl_info dlip;
	static char buf[80];

	if (dladdr((void *) fn, &dlip)) {
		int offset;

		address = dlsym(RTLD_DEFAULT, dlip.dli_sname);
		offset = ((char *) fn) - ((char *) address);
		if (offset == 0) {
			log_message(MSG_FC_DEBUG, "%s: tracing %s()\n",
			    dlip.dli_fname, dlip.dli_sname);
		} else {
			log_message(MSG_FC_DEBUG, "%s: tracing %s%s0x%x()\n",
			    dlip.dli_fname, dlip.dli_sname,
			    ((offset < 0) ? "-" : "+"),
			    ((offset < 0) ? -offset : offset));
		}
	} else {
		log_message(MSG_FC_DEBUG, "do_fclib_trace: <Unknown> %p\n", fn);
	}
	if (trace_fn)
		trace_fn(env);
}

void
output_step_message(fcode_env_t *env)
{
	log_message(MSG_INFO, "Step keys: <space>, Continue, Forth, Go,"
	    " Help, Step, Quit\n");
}

void
enable_step(fcode_env_t *env)
{
	output_step_message(env);
	set_level(DEBUG_STEPPING);
}


void
disable_step(fcode_env_t *env)
{
	unset_level(DEBUG_STEPPING);
}

/*
 * Output of state info is done elsewhere
 */
int
do_fclib_step(fcode_env_t *env)
{
	int c;
	fcode_env_t *new_env;

	for (; ; ) {
		c = getchar();
		if (c != '\n') {
			while (getchar() != '\n')
				;
		}
		switch (c) {
		case EOF:
		case 'q':
			unbug(env);
			IP = 0;
			return (1);

		case 'c':
			debug_set_level(env,
			    DEBUG_EXEC_TRACE|DEBUG_EXEC_DUMP_DS);
			break;

		case 'g':
			unbug(env);
			break;

		case 'f':
			unset_level(DEBUG_STEPPING);
			new_env = clone_environment(env, NULL);
			do_interact(new_env);
			destroy_environment(new_env);
			set_level(DEBUG_STEPPING);
			continue;

		case ' ':
		case '\n':
			break;

		case 'd':	/* Unimplemented */
		case 'u':	/* Unimplemented */
		default:
			output_step_message(env);
			continue;
		}
		break;
	}
	return (0);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;


	FORTH(0,	"stack-trace",		enable_stack_trace);
	FORTH(0,	"no-stack-trace",	disable_stack_trace);
	FORTH(0,	"trace-on",		enable_trace);
	FORTH(0,	"trace-off",		disable_trace);
	FORTH(0,	"call-trace",		call_trace);
	FORTH(0,	"no-call-trace",	no_call_trace);
	FORTH(0,	"step-on",		enable_step);
	FORTH(0,	"step-off",		disable_step);
}

#endif
