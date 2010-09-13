/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.   All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcode/private.h>
#include <fcode/log.h>

fcode_env_t *initial_env = 0;
int dict_size = 0x4000000;	/* 64Mb, hopefully big enough... */
int stack_size = 0x200;

void *
safe_malloc(size_t n, char *f, int l)
{
	void *p;

	p = malloc((size_t)n);
#if defined(__sparcv9)
	/*
	 * For Ultrasparc, we must force addresses to be less than 4Gb,
	 * since Fcode assumes that addresses can be stored in 32 bits.
	 * To get around this would require turning all addresses into
	 * cookies, which is a lot of work.
	 */
	if (((uint64_t)p) >= 0x100000000) {
		log_message(MSG_WARN, "Malloc returned address > 4Gb\n");
	}
#endif	/* __sparcv9 */
	if (p) {
		memset(p, 0, (size_t)n);
	} else
		log_message(MSG_ERROR, "%s:%d:Malloc(%llx) failed\n", f, l,
		    (uint64_t)n);
	return (p);
}

void *
safe_realloc(void *p, size_t n, char *f, int l)
{
	void *newp;

	if ((newp = safe_malloc(n, f, l)) == NULL) {
		log_message(MSG_ERROR, "%s:%d:realloc(%p, %x) failed\n", f, l,
		    p, n);
		safe_free(p, f, l);
		return (NULL);
	}
	if (p) {
		memcpy(newp, p, n);
		safe_free(p, f, l);
	}
	return (newp);
}

void
safe_free(void *p, char *f, int l)
{
	if (p) {
		free(p);
	}
}

char *
safe_strdup(char *s, char *f, int l)
{
	char *p = strdup(s);

	return (p);
}

#pragma init(_init)

static void
_init(void)
{
	int i;
	acf_t f_error_addr;
	fcode_env_t *env;

	NOTICE;

	fcode_impl_count = 0;
	env = MALLOC(sizeof (fcode_env_t));
	env->table = MALLOC((MAX_FCODE + 1) * sizeof (fcode_token));
	env->base = MALLOC(dict_size);
	env->here = env->base;
	env->ds = env->ds0 = MALLOC(stack_size * sizeof (fstack_t));
	env->rs = env->rs0 = MALLOC(stack_size * sizeof (fstack_t));
	env->order = MALLOC(MAX_ORDER * sizeof (token_t));
	env->input = MALLOC(sizeof (input_typ));
	env->num_base = 0x10;

	/* Setup the initial forth environment */
	do_forth(env);
	do_definitions(env);
	install_handlers(env);

	initial_env = env;

	/*
	 * Need to define this early because it is the default for
	 * all unimpl, FCODE functions
	 */
	P1275(0x0fc, IMMEDIATE,	"ferror",		f_error);
	f_error_addr = LINK_TO_ACF(env->lastlink);
	for (i = 0; i <= MAX_FCODE; i++) {
		DEBUGF(ANY, env->table[i].usage = 0);
		SET_TOKEN(i, IMMEDIATE, "ferror", f_error_addr);
	}
	fcode_impl_count = 0;
}
