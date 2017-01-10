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
 * Copyright (c) 1993-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_SEMAPHORE_H
#define	_SYS_SEMAPHORE_H

/*
 * Public interface to semaphores.  See semaphore(9F) for details.
 */

#ifndef	_ASM

#ifdef _KERNEL
#include <sys/thread.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	SEMA_DEFAULT,
	SEMA_DRIVER
} ksema_type_t;

typedef struct _ksema {
	void	* _opaque[2];	/* 2 words on 4 byte alignment */
} ksema_t;

#if defined(_KERNEL)

#define	SEMA_HELD(x)		(sema_held((x)))

extern	void	sema_init(ksema_t *, uint32_t, char *, ksema_type_t, void *);
extern	void	sema_destroy(ksema_t *);
extern	void	sema_p(ksema_t *);
extern	int	sema_p_sig(ksema_t *);
extern	void	sema_v(ksema_t *);
extern	int	sema_tryp(ksema_t *);
extern	int	sema_held(ksema_t *);

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM */

#endif	/* _SYS_SEMAPHORE_H */
