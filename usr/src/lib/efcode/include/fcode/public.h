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

#ifndef	_FCODE_PUBLIC_H
#define	_FCODE_PUBLIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * these are the public interfaces to the fcode interpretter
 */

void define_word(fcode_env_t *, int, char *, void (*)(fcode_env_t *));
void push_ds(fcode_env_t *, fstack_t);
void push_rs(fcode_env_t *, fstack_t);
fstack_t pop_ds(fcode_env_t *);
fstack_t pop_rs(fcode_env_t *);

void run_fcode(fcode_env_t *, uchar_t *, int);
void destroy_environment(fcode_env_t *);
void begin_package(fcode_env_t *);
void end_package(fcode_env_t *);
fcode_env_t *clone_environment(fcode_env_t *, void *);

void set_interpreter_debug_level(long);
long get_interpreter_debug_level(void);

#ifdef	__cplusplus
}
#endif

#endif /* _FCODE_PUBLIC_H */
