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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_X_CALL_H
#define	_SYS_X_CALL_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

typedef uintptr_t xc_arg_t;
typedef int (*xc_func_t)(xc_arg_t, xc_arg_t, xc_arg_t);

/*
 * One of these is stored in each CPU's machcpu data, plus one extra for
 * priority (ie panic) messages
 */
typedef struct xc_data {
	xc_func_t	xc_func;
	xc_arg_t	xc_a1;
	xc_arg_t	xc_a2;
	xc_arg_t	xc_a3;
} xc_data_t;

/*
 * This is kept as small as possible, since for N CPUs we need N * N of them.
 */
typedef struct xc_msg {
	uint8_t		xc_command;
#ifdef __amd64
	uint16_t	xc_master;
	uint16_t	xc_slave;
#else
	uint8_t		xc_master;
	uint8_t		xc_slave;
#endif
	struct xc_msg	*xc_next;
} xc_msg_t;

/*
 * Cross-call routines.
 */
#if defined(_KERNEL)

extern void	xc_init_cpu(struct cpu *);
extern void	xc_fini_cpu(struct cpu *);
extern int	xc_flush_cpu(struct cpu *);
extern uint_t	xc_serv(caddr_t, caddr_t);

#define	CPUSET2BV(set)	((ulong_t *)(void *)&(set))
extern void	xc_call(xc_arg_t, xc_arg_t, xc_arg_t, ulong_t *, xc_func_t);
extern void	xc_call_nowait(xc_arg_t, xc_arg_t, xc_arg_t, ulong_t *,
    xc_func_t);
extern void	xc_sync(xc_arg_t, xc_arg_t, xc_arg_t, ulong_t *, xc_func_t);
extern void	xc_priority(xc_arg_t, xc_arg_t, xc_arg_t, ulong_t *, xc_func_t);

#endif	/* _KERNEL */

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_X_CALL_H */
