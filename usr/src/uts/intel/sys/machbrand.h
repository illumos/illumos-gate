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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_MACHBRAND_H
#define	_SYS_MACHBRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

#include <sys/model.h>

struct brand_mach_ops {
	void	(*b_sysenter)(void);
	void	(*b_int80)(void);
	void	(*b_int91)(void);
	void	(*b_syscall)(void);
	void	(*b_syscall32)(void);
	greg_t	(*b_fixsegreg)(greg_t, model_t);
	uintptr_t (*b_fsbase)(klwp_t *, uintptr_t);
};

#endif	/* _ASM */

#define	BRAND_CB_SYSENTER	0
#define	BRAND_CB_INT80		1
#define	BRAND_CB_INT91		2
#define	BRAND_CB_SYSCALL	3
#define	BRAND_CB_SYSCALL32	4

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHBRAND_H */
