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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _COMPAT_FREEBSD_SYS_CALLOUT_H_
#define	_COMPAT_FREEBSD_SYS_CALLOUT_H_

#include <sys/cyclic.h>

struct callout {
	cyclic_id_t	c_cyc_id;
	hrtime_t	c_target;
	hrtime_t	c_fired;
	void		(*c_func)(void *);
	void		*c_arg;
};

#define	C_ABSOLUTE		0x0200	/* event time is absolute. */

/* Callout considered active if t_target has not been zeroed */
#define	callout_active(c)	((c)->c_target != 0)
#define	callout_deactivate(c)	((c)->c_target = 0)

/*
 * If a callout is rescheduled (into the future) while its handler is running,
 * it will be able to detect the pending invocation by the target time being
 * greater than the time at which the handler was fired.
 *
 * This is only valid when checked from the callout handler, which is the only
 * place where it is used by bhyve today.
 */
#define	callout_pending(c)	((c)->c_target > (c)->c_fired)

void vmm_glue_callout_init(struct callout *c, int mpsafe);
void vmm_glue_callout_stop(struct callout *c);
void vmm_glue_callout_drain(struct callout *c);

/* illumos-custom function for resource locality optimization */
void	vmm_glue_callout_localize(struct callout *c);

static __inline void
callout_init(struct callout *c, int mpsafe)
{
	vmm_glue_callout_init(c, mpsafe);
}

static __inline void
callout_stop(struct callout *c)
{
	vmm_glue_callout_stop(c);
}

static __inline void
callout_drain(struct callout *c)
{
	vmm_glue_callout_drain(c);
}

void callout_reset_hrtime(struct callout *c, hrtime_t target,
    void (*func)(void *), void *arg, int flags);

uint64_t hrt_freq_count(hrtime_t interval, uint32_t freq);
hrtime_t hrt_freq_interval(uint32_t freq, uint64_t count);

#endif	/* _COMPAT_FREEBSD_SYS_CALLOUT_H_ */
