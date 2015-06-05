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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_KLWP_H
#define	_SYS_KLWP_H

#include <sys/types.h>
#include <sys/condvar.h>
#include <sys/thread.h>
#include <sys/signal.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The light-weight process object and the methods by which it
 * is accessed.
 */

#define	MAXSYSARGS	8	/* Maximum # of arguments passed to a syscall */

/* lwp_eosys values */
#define	NORMALRETURN	0	/* normal return; adjusts PC, registers */
#define	JUSTRETURN	1	/* just return, leave registers alone */

typedef struct _klwp	*klwp_id_t;

typedef struct _klwp {
	/*
	 * linkage
	 */
	struct _kthread	*lwp_thread;
	struct proc	*lwp_procp;

} klwp_t;

/* lwp states */
#define	LWP_USER	0x01		/* Running in user mode */
#define	LWP_SYS		0x02		/* Running in kernel mode */

#if	defined(_KERNEL)
extern	volatile int	lwp_default_stksize;
extern	klwp_t		lwp0;

/* where newly-created lwps normally start */
extern	void	lwp_rtt(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KLWP_H */
