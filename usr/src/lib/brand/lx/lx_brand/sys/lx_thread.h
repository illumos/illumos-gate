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
 * Copyright 2006 Sun Microsystems, Inc.	All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc
 */

#ifndef _SYS_LX_THREAD_H
#define	_SYS_LX_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/lx_signal.h>
#include <thread.h>

typedef enum lx_exit_type {
	LX_ET_NONE = 0,
	LX_ET_EXIT,
	LX_ET_EXIT_GROUP
} lx_exit_type_t;

typedef struct lx_tsd {
	/* per-thread flag set on parent vfork, cleared on thread resume */
	int		lxtsd_is_vforked;
	lx_exit_type_t	lxtsd_exit;
	int		lxtsd_exit_status;
	ucontext_t	lxtsd_exit_context;

	/*
	 * If this value is non-zero, we use it in lx_sigdeliver() to represent
	 * the in-use extent of the Linux (i.e. BRAND) stack for this thread.
	 * Access to this value must be protected by _sigoff()/_sigon().
	 */
	uintptr_t	lxtsd_lx_sp;

	/*
	 * Alternate stack for Linux sigaltstack emulation:
	 */
	lx_stack_t	lxtsd_sigaltstack;

	void		*lxtsd_clone_state;

	lx_sigbackup_t	*lxtsd_sigbackup;
} lx_tsd_t;

extern thread_key_t	lx_tsd_key;

extern void		lx_swap_gs(long, long *);

extern void		lx_exit_common(void) __NORETURN;

extern lx_tsd_t		*lx_get_tsd(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_THREAD_H */
