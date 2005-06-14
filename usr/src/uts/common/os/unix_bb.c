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
 * Copyright (c) 1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Kernel Basic Block Profiling - profiling initialization hooks
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/spl.h>
#include <sys/unix_bb_info.h>

#ifdef KCOV

/*
 * routines to do kernel basic block coverage.
 */

struct bb_info	*unix_bb_list;
lock_t		unix_bb_lock;

/*
 *  There is the potential that we will be called by any C routine.
 *  So we avoid calling any C routines from here, as we'll get
 *  a recursive call.
 *  Also, we wish to avoid a deadlock due to being called by
 *  an interrupt handler, so we lock at the NMI level.
 *  Of course, that leaves the possibility that we'll
 *  be called from an NMI handler.  If the lock is available,
 *  fine, otherwise, if we're on the interrupt stack at the
 *  NMI level, we just return.
 *
 *  We will probably get another chance to add the bb_info structure
 *  to the list, since the bb_info structure is for the entire object file.
 */
#ifdef	KCOV_TEST
int		unix_bb_a, unix_bb_b, unix_bb_c;
int		unix_bb_d, unix_bb_e, unix_bb_f, unix_bb_g;
processorid_t	bb_last_who;
char 		*bb_last_where;
#endif

void
__bb_init_func(struct bb_info *bb)
{
	u_short s;

/*
 *	a = c + g
 *	b = c + d
 *	a = c + e
 *	e = g
 *
 *	a->b->c
 *	a->b->d->e->g
 *	a->b->d->e->f->g
 *	a->e->g
 *	a->e->f->g
 */

	/*
	 *  Raise the pil and try to get the lock.
	 */
	s = spl8();
#ifdef	KCOV_TEST
	unix_bb_a++;
#endif

	if (!lock_try(&unix_bb_lock)) {
		/*
		 *  If we're on the interrrupt stack, we just return
		 *  in case it's an NMI and we're looking at a deadlock
		 *  situation.  Otherwise, we use lock_set_spl()
		 */
#ifdef	KCOV_TEST
		unix_bb_b++;
#endif
		if (CPU_ON_INTR(CPU)) {
#ifdef	KCOV_TEST
			unix_bb_c++;
#endif
			splx(s);
			return;
		}
#ifdef	KCOV_TEST
		unix_bb_d++;
#endif
		splx(s);
		lock_set_spl(&unix_bb_lock, ipltospl(NMI_LEVEL), &s);
	}

#ifdef	KCOV_TEST
	bb_last_who = CPU->cpu_id;
	bb_last_where = bb->bb_filename;
	unix_bb_e++;
#endif
	/*
	 *  We've got the lock.  If we have not been initialized, add us
	 *  to the list and set the initialized flag.
	 */
#ifdef	KCOV_TEST
	if (bb->bb_next == 0) {
		unix_bb_f++;
#else
	if (bb->bb_initflag == 0) {
		bb->bb_initflag = 1;
#endif
		bb->bb_next = unix_bb_list;
		unix_bb_list = bb;
	}

#ifdef	KCOV_TEST
	unix_bb_g++;
#endif
	lock_clear_splx(&unix_bb_lock, s);
}
#endif /* KCOV */
