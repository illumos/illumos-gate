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
 */

#ifndef _COMPAT_FREEBSD_SYS_CALLOUT_H_
#define	_COMPAT_FREEBSD_SYS_CALLOUT_H_

#include <sys/cyclic.h>

struct callout {
	cyclic_id_t	c_cyc_id;
	int		c_flags;
	void		(*c_func)(void *);
	void		*c_arg;

};

#define	CALLOUT_ACTIVE		0x0002	/* callout is currently active */
#define	CALLOUT_PENDING		0x0004	/* callout is waiting for timeout */

#define	C_ABSOLUTE		0x0200	/* event time is absolute. */

#define	callout_active(c)	((c)->c_flags & CALLOUT_ACTIVE)
#define	callout_deactivate(c)	((c)->c_flags &= ~CALLOUT_ACTIVE)
#define	callout_pending(c)	((c)->c_flags & CALLOUT_PENDING)

void	vmm_glue_callout_init(struct callout *c, int mpsafe);
int	vmm_glue_callout_reset_sbt(struct callout *c, sbintime_t sbt,
    sbintime_t pr, void (*func)(void *), void *arg, int flags);
int	vmm_glue_callout_stop(struct callout *c);
int	vmm_glue_callout_drain(struct callout *c);

/* illumos-custom function for resource locality optimization */
void	vmm_glue_callout_localize(struct callout *c);

static __inline void
callout_init(struct callout *c, int mpsafe)
{
	vmm_glue_callout_init(c, mpsafe);
}

static __inline int
callout_stop(struct callout *c)
{
	return (vmm_glue_callout_stop(c));
}

static __inline int
callout_drain(struct callout *c)
{
	return (vmm_glue_callout_drain(c));
}

static __inline int
callout_reset_sbt(struct callout *c, sbintime_t sbt, sbintime_t pr,
    void (*func)(void *), void *arg, int flags)
{
	return (vmm_glue_callout_reset_sbt(c, sbt, pr, func, arg, flags));
}


#endif	/* _COMPAT_FREEBSD_SYS_CALLOUT_H_ */
