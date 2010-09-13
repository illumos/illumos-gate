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

#ifndef	_FCODE_PRIVATE_H
#define	_FCODE_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef DEBUG
#include <fcode/debug.h>

#ifdef	__cplusplus
extern "C" {
#endif

long get_interpreter_debug_level(void);
void set_interpreter_debug_level(long lvl);

#define	DPRINTF(x, y)	if (get_interpreter_debug_level() & (DEBUG_##x))\
			    printf y
#define	DEBUGF(x, y)	if (get_interpreter_debug_level() & (DEBUG_##x))\
			    { y; }
#else

#ifdef	__cplusplus
extern "C" {
#endif

#define	DPRINTF(x, y)
#define	DEBUGF(x, y)
#endif

#define	PUSH(sp, n)	*(++sp) = (n)
#define	POP(sp)		*(sp--)

#define	ERROR(x)	printf x

#define	MALLOC(x)	safe_malloc((x), __FILE__, __LINE__)
#define	REALLOC(x, n)	safe_realloc((x), (n), __FILE__, __LINE__)
#define	STRDUP(x)	safe_strdup((x), __FILE__, __LINE__)
#define	FREE(x)		safe_free((x), __FILE__, __LINE__)

#include <fcode/engine.h>

extern fcode_env_t *initial_env;
extern int fcode_impl_count;

#define	SET_TOKEN(t, f, n, a) \
	env->table[t].flags = f; \
	env->table[t].name = n; \
	env->table[t].apf = a;

#define	FCODE(token, fl, nm, fnc) \
	fcode_impl_count++; \
	env->table[token].flags = fl; \
	do_code(env, token, nm, fnc);

#define	ANSI(tk, t, nm, fnc)	FCODE(tk, (ANSI_WORD|P1275_WORD|t), nm, fnc)
#define	P1275(tk, t, nm, fnc)	FCODE(tk, (P1275_WORD|t), nm, fnc)

#ifdef DEBUG
#define	ASSERT(x)	if (!(x)) printf("%s:%d: ASSERT FAILED!!\n",\
			    __FILE__, __LINE__);
#ifdef NOTICE
#undef NOTICE
#define	NOTICE	printf("%s:%d: _init called\n", __FILE__, __LINE__)
#else
#define	NOTICE
#endif
#else
#define	ASSERT(x)
#define	NOTICE
#endif

void fc_abort(fcode_env_t *, char *type);

#define	TODO	fc_abort(env, "TODO")
#define	FATAL	ERROR(("%s:%d: MANGLED FCODE!! Fatal Error\n",\
		    __FILE__, __LINE__)))

#ifndef USE_INTERRUPTS
#define	CHECK_INTERRUPT
#define	COMPLETE_INTERRUPT
#else
#define	CHECK_INTERRUPT		check_interrupt()
#define	COMPLETE_INTERRUPT	complete_interrupt()
#endif

/* dforth_t manimpulations */
#define	MAKE_DFORTH(hi, lo)	((((u_dforth_t)(hi) << 32)) | \
	    (((u_dforth_t)(lo)) & 0xffffffff))
#define	DFORTH_LO(df)	(((u_dforth_t)(df)) & 0xffffffff)
#define	DFORTH_HI(df)	((((u_dforth_t)(df)) >> 32) & 0xffffffff)

#define	TRUE	(-1)
#define	FALSE	(0)


instance_t *open_instance_chain(fcode_env_t *, device_t *, int);
void close_instance_chain(fcode_env_t *, instance_t *, int);
void activate_device(fcode_env_t *, device_t *);
void deactivate_device(fcode_env_t *, device_t *);

void install_handlers(fcode_env_t *);
void set_defer_actions(fcode_env_t *, int);
void throw_from_fclib(fcode_env_t *, fstack_t, char *, ...);
int get_default_intprop(fcode_env_t *, char *, device_t *, int);
uint_t get_number_of_parent_address_cells(fcode_env_t *);
char *get_package_name(fcode_env_t *, device_t *);

token_t *get_instance_address(fcode_env_t *);
fc_resource_t *find_resource(fc_resource_t **, void *,
    int (c)(void *, void *));
void *add_resource(fc_resource_t **, void *, int (c)(void *, void *));
void free_resource(fc_resource_t **, void *, int (c)(void *, void *));
void set_temporary_compile(fcode_env_t *);
void temporary_execute(fcode_env_t *);
prop_t *lookup_package_property(fcode_env_t *, char *, device_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _FCODE_PRIVATE_H */
