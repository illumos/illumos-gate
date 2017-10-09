/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/times.h>
#include <sys/msacct.h>
#include <sys/lx_userhz.h>

/* See the comment on LX_USERHZ for more details. */
#define	LX_NSEC_PER_USERHZ	(NANOSEC / LX_USERHZ)
#define	NSEC_TO_LX_USERHZ(nsec)	((nsec) / LX_NSEC_PER_USERHZ)

/*
 * Our times(2) implementation is based on the native times(2), but with
 * the necessary scaling to adjust to USER_HZ. Also, Linux avoids writing
 * to a NULL tp, whereas our native code returns EFAULT.
 */
long
lx_times(struct tms *tp)
{
	proc_t *p = curproc;
	struct tms p_time;
	clock_t ret_lbolt;

	mutex_enter(&p->p_lock);
	p_time.tms_utime =
	    (clock_t)NSEC_TO_LX_USERHZ(mstate_aggr_state(p, LMS_USER));
	p_time.tms_stime =
	    (clock_t)NSEC_TO_LX_USERHZ(mstate_aggr_state(p, LMS_SYSTEM));
	p_time.tms_cutime = HZ_TO_LX_USERHZ(p->p_cutime);
	p_time.tms_cstime = HZ_TO_LX_USERHZ(p->p_cstime);
	mutex_exit(&p->p_lock);

#ifdef _SYSCALL32_IMPL
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		struct tms32 t32;

		t32.tms_utime = p_time.tms_utime;
		t32.tms_stime = p_time.tms_stime;
		t32.tms_cutime = p_time.tms_cutime;
		t32.tms_cstime = p_time.tms_cstime;

		if (tp != NULL && copyout(&t32, tp, sizeof (t32)) != 0)
			return (set_errno(EFAULT));

		ret_lbolt = ddi_get_lbolt();
		return ((clock32_t)HZ_TO_LX_USERHZ(ret_lbolt));
	} else
#endif /* _SYSCALL32_IMPL */
	{
		if (tp != NULL && copyout(&p_time, tp, sizeof (p_time)) != 0)
			return (set_errno(EFAULT));

		ret_lbolt = ddi_get_lbolt();
		return (HZ_TO_LX_USERHZ(ret_lbolt));
	}
}
