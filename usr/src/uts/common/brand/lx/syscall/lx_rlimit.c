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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/zone.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/lx_impl.h>
#include <sys/lx_brand.h>

#define	LX_RLIMIT_CPU		0
#define	LX_RLIMIT_FSIZE		1
#define	LX_RLIMIT_DATA		2
#define	LX_RLIMIT_STACK		3
#define	LX_RLIMIT_CORE		4
#define	LX_RLIMIT_RSS		5
#define	LX_RLIMIT_NPROC		6
#define	LX_RLIMIT_NOFILE	7
#define	LX_RLIMIT_MEMLOCK	8
#define	LX_RLIMIT_AS		9
#define	LX_RLIMIT_LOCKS		10	/* NA limit on locks, early 2.4 only */
#define	LX_RLIMIT_SIGPENDING	11
#define	LX_RLIMIT_MSGQUEUE	12
#define	LX_RLIMIT_NICE		13	/* NA ceiling for nice */
#define	LX_RLIMIT_RTPRIO	14	/* NA ceiling on the RT priority */
#define	LX_RLIMIT_RTTIME	15	/* NA cpu limit for RT proc. */

#define	LX_RLIMIT_NLIMITS	16

#define	RCTL_INFINITE(x) \
	((x->rcv_flagaction & RCTL_LOCAL_MAXIMAL) && \
	(x->rcv_flagaction & RCTL_GLOBAL_INFINITE))

typedef struct {
	ulong_t	rlim_cur;
	ulong_t	rlim_max;
} lx_rlimit_t;

typedef struct {
	uint32_t	rlim_cur;
	uint32_t	rlim_max;
} lx_rlimit32_t;

/*
 * Linux supports many of the same resources that we do, but on illumos these
 * are rctls. Instead of using rlimit, we use rctls for all of the limits.
 * This table is used to translate Linux rlimit keys into the illumos legacy
 * rlimit. We then primarily use the rctl/rlimit compatability code to
 * manage these.
 */
static int l_to_r[LX_RLIMIT_NLIMITS] = {
	RLIMIT_CPU,		/* 0 CPU */
	RLIMIT_FSIZE,		/* 1 FSIZE */
	RLIMIT_DATA,		/* 2 DATA */
	RLIMIT_STACK,		/* 3 STACK */
	RLIMIT_CORE,		/* 4 CORE */
	-1,			/* 5 RSS */
	-1,			/* 6 NPROC */
	RLIMIT_NOFILE,		/* 7 NOFILE */
	-1,			/* 8 MEMLOCK */
	RLIMIT_AS,		/* 9 AS */
	-1,			/* 10 LOCKS */
	-1, 			/* 11 SIGPENDING */
	-1, 			/* 12 MSGQUEUE */
	-1,			/* 13 NICE */
	-1,			/* 14 RTPRIO */
	-1			/* 15 RTTIME */
};

/*
 * Magic value Linux uses to indicate infinity
 */
#define	LX_RLIM_INFINITY_N	ULONG_MAX

static void
lx_get_rctl(char *nm, struct rlimit64 *rlp64)
{
	rctl_hndl_t hndl;
	rctl_val_t *oval, *nval;

	rlp64->rlim_cur = RLIM_INFINITY;
	rlp64->rlim_max = RLIM_INFINITY;

	nval = kmem_alloc(sizeof (rctl_val_t), KM_SLEEP);
	mutex_enter(&curproc->p_lock);

	hndl = rctl_hndl_lookup(nm);
	oval = NULL;
	while ((hndl != -1) && rctl_local_get(hndl, oval, nval, curproc) == 0) {
		oval = nval;
		switch (nval->rcv_privilege) {
		case RCPRIV_BASIC:
			if (!RCTL_INFINITE(nval))
				rlp64->rlim_cur = nval->rcv_value;
			break;
		case RCPRIV_PRIVILEGED:
			if (!RCTL_INFINITE(nval))
				rlp64->rlim_max = nval->rcv_value;
			break;
		}
	}

	mutex_exit(&curproc->p_lock);
	kmem_free(nval, sizeof (rctl_val_t));

	if (rlp64->rlim_cur == RLIM_INFINITY &&
	    rlp64->rlim_max != RLIM_INFINITY)
		rlp64->rlim_cur = rlp64->rlim_max;
}

static int
lx_getrlimit_common(int lx_resource, uint64_t *rlim_curp, uint64_t *rlim_maxp)
{
	lx_proc_data_t *pd = ptolxproc(curproc);
	int resource;
	int64_t cur = -1;
	boolean_t cur_inf = B_FALSE;
	int64_t max = -1;
	boolean_t max_inf = B_FALSE;
	struct rlimit64 rlim64;

	if (lx_resource < 0 || lx_resource >= LX_RLIMIT_NLIMITS)
		return (EINVAL);

	switch (lx_resource) {
	case LX_RLIMIT_LOCKS:
		rlim64.rlim_cur = pd->l_fake_limits[LX_RLFAKE_LOCKS].rlim_cur;
		rlim64.rlim_max = pd->l_fake_limits[LX_RLFAKE_LOCKS].rlim_max;
		break;

	case LX_RLIMIT_NICE:
		rlim64.rlim_cur = pd->l_fake_limits[LX_RLFAKE_NICE].rlim_cur;
		rlim64.rlim_max = pd->l_fake_limits[LX_RLFAKE_NICE].rlim_max;
		break;

	case LX_RLIMIT_RTPRIO:
		rlim64.rlim_cur = pd->l_fake_limits[LX_RLFAKE_RTPRIO].rlim_cur;
		rlim64.rlim_max = pd->l_fake_limits[LX_RLFAKE_RTPRIO].rlim_max;
		break;

	case LX_RLIMIT_RTTIME:
		rlim64.rlim_cur = pd->l_fake_limits[LX_RLFAKE_RTTIME].rlim_cur;
		rlim64.rlim_max = pd->l_fake_limits[LX_RLFAKE_RTTIME].rlim_max;
		break;

	case LX_RLIMIT_RSS:
		/* zone.max-physical-memory */
		rlim64.rlim_cur = rlim64.rlim_max = curzone->zone_phys_mem_ctl;
		break;

	case LX_RLIMIT_NPROC:
		/*  zone.max-lwps */
		rlim64.rlim_cur = rlim64.rlim_max = curzone->zone_nlwps_ctl;
		break;

	case LX_RLIMIT_MEMLOCK:
		lx_get_rctl("process.max-locked-memory", &rlim64);

		/* If unlimited, use zone.max-locked-memory */
		if (rlim64.rlim_max == RLIM64_INFINITY)
			rlim64.rlim_max = curzone->zone_locked_mem_ctl;
		if (rlim64.rlim_cur == RLIM64_INFINITY)
			rlim64.rlim_cur = curzone->zone_locked_mem_ctl;
		break;

	case LX_RLIMIT_SIGPENDING:
		lx_get_rctl("process.max-sigqueue-size", &rlim64);
		break;

	case LX_RLIMIT_MSGQUEUE:
		lx_get_rctl("process.max-msg-messages", &rlim64);
		break;

	default:
		resource = l_to_r[lx_resource];

		mutex_enter(&curproc->p_lock);
		(void) rctl_rlimit_get(rctlproc_legacy[resource], curproc,
		    &rlim64);
		mutex_exit(&curproc->p_lock);
		break;
	}


	if (rlim64.rlim_cur == RLIM64_INFINITY) {
		cur = LX_RLIM_INFINITY_N;
	} else {
		cur = rlim64.rlim_cur;
	}
	if (rlim64.rlim_max == RLIM64_INFINITY) {
		max = LX_RLIM_INFINITY_N;
	} else {
		max = rlim64.rlim_max;
	}

	if (lx_resource == LX_RLIMIT_STACK && cur > INT_MAX) {
		/*
		 * Stunningly, Linux has somehow managed to confuse the concept
		 * of a "limit" with that of a "default" -- and the value of
		 * RLIMIT_STACK is used by NPTL as the _default_ stack size if
		 * it isn't specified. (!!)  Even for a system that prides
		 * itself on slapdash castles of junk, this is an amazingly
		 * willful act of incompetence -- and one that is gleefully
		 * confessed in the pthread_create() man page: "if the
		 * RLIMIT_STACK soft resource limit at the time the program
		 * started has any value other than 'unlimited', then it
		 * determines the default stack size of new threads."  A
		 * typical stack limit for us is 32TB; if it needs to be said,
		 * setting the default stack size to be 32TB doesn't work so
		 * well!  Of course, glibc dropping a deuce in its pants
		 * becomes our problem -- so to prevent smelly accidents we
		 * tell Linux that any stack limit over the old (32-bit) values
		 * for infinity are just infinitely large.
		 */
		cur_inf = B_TRUE;
		max_inf = B_TRUE;
	}

	if (cur_inf) {
		*rlim_curp = LX_RLIM64_INFINITY;
	} else {
		*rlim_curp = cur;
	}

	if (max_inf) {
		*rlim_maxp = LX_RLIM64_INFINITY;
	} else {
		*rlim_maxp = max;
	}

	return (0);
}

/*
 * This is the 'new' getrlimit, variously called getrlimit or ugetrlimit
 * in Linux headers and code.  The only difference between this and the old
 * getrlimit (variously called getrlimit or old_getrlimit) is the value of
 * RLIM_INFINITY, which is smaller for the older version.  Modern code will
 * use this version by default.
 */
long
lx_getrlimit(int resource, lx_rlimit_t *rlp)
{
	int rv;
	lx_rlimit_t rl;
	uint64_t rlim_cur, rlim_max;

	rv = lx_getrlimit_common(resource, &rlim_cur, &rlim_max);
	if (rv != 0)
		return (set_errno(rv));

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (rlim_cur == LX_RLIM64_INFINITY)
			rl.rlim_cur = LX_RLIM_INFINITY_N;
		else if (rlim_cur > LX_RLIM_INFINITY_N)
			rl.rlim_cur = LX_RLIM_INFINITY_N;
		else
			rl.rlim_cur = (ulong_t)rlim_cur;

		if (rlim_max == LX_RLIM64_INFINITY)
			rl.rlim_max = LX_RLIM_INFINITY_N;
		else if (rlim_max > LX_RLIM_INFINITY_N)
			rl.rlim_max = LX_RLIM_INFINITY_N;
		else
			rl.rlim_max = (ulong_t)rlim_max;

		if (copyout(&rl, rlp, sizeof (rl)) != 0)
			return (set_errno(EFAULT));
	}
#ifdef _SYSCALL32_IMPL
	else {
		lx_rlimit32_t rl32;

		if (rlim_cur > UINT_MAX)
			rl.rlim_cur = UINT_MAX;
		else
			rl.rlim_cur = (ulong_t)rlim_cur;

		if (rlim_max > UINT_MAX)
			rl.rlim_max = UINT_MAX;
		else
			rl.rlim_max = (ulong_t)rlim_max;

		rl32.rlim_cur = rl.rlim_cur;
		rl32.rlim_max = rl.rlim_max;

		if (copyout(&rl32, rlp, sizeof (rl32)) != 0)
			return (set_errno(EFAULT));
	}
#endif

	return (0);
}

/*
 * This is the 'old' getrlimit, variously called getrlimit or old_getrlimit
 * in Linux headers and code.  The only difference between this and the new
 * getrlimit (variously called getrlimit or ugetrlimit) is the value of
 * RLIM_INFINITY, which is smaller for the older version.
 *
 * This is only used for 32-bit code.
 */
long
lx_oldgetrlimit(int resource, lx_rlimit_t *rlp)
{
	int rv;
	lx_rlimit32_t rl32;
	uint64_t rlim_cur, rlim_max;

	rv = lx_getrlimit_common(resource, &rlim_cur, &rlim_max);
	if (rv != 0)
		return (set_errno(rv));

	if (rlim_cur > INT_MAX)
		rl32.rlim_cur = INT_MAX;
	else
		rl32.rlim_cur = (ulong_t)rlim_cur;

	if (rlim_max > INT_MAX)
		rl32.rlim_max = INT_MAX;
	else
		rl32.rlim_max = (ulong_t)rlim_cur;

	if (copyout(&rl32, rlp, sizeof (rl32)) != 0)
		return (set_errno(EFAULT));

	return (0);
}

static int
lx_set_rctl(char *nm, struct rlimit64 *rlp64)
{
	int err;
	rctl_hndl_t hndl;
	rctl_alloc_gp_t *gp;

	gp = rctl_rlimit_set_prealloc(1);

	mutex_enter(&curproc->p_lock);

	hndl = rctl_hndl_lookup(nm);

	/*
	 * We're not supposed to do this but since we want all our rctls to
	 * behave like rlimits, we take advantage of this function to set up
	 * this way.
	 */
	err = rctl_rlimit_set(hndl, curproc, rlp64, gp, RCTL_LOCAL_DENY, 0,
	    CRED());

	mutex_exit(&curproc->p_lock);

	rctl_prealloc_destroy(gp);

	return (err);
}

static int
lx_setrlimit_common(int lx_resource, uint64_t rlim_cur, uint64_t rlim_max)
{
	lx_proc_data_t *pd = ptolxproc(curproc);
	int err;
	int resource;
	rctl_alloc_gp_t *gp;
	struct rlimit64 rl64;

	if (lx_resource < 0 || lx_resource >= LX_RLIMIT_NLIMITS)
		return (EINVAL);

	switch (lx_resource) {
	case LX_RLIMIT_LOCKS:
		pd->l_fake_limits[LX_RLFAKE_LOCKS].rlim_cur = rlim_cur;
		pd->l_fake_limits[LX_RLFAKE_LOCKS].rlim_max = rlim_max;
		break;

	case LX_RLIMIT_NICE:
		pd->l_fake_limits[LX_RLFAKE_NICE].rlim_cur = rlim_cur;
		pd->l_fake_limits[LX_RLFAKE_NICE].rlim_max = rlim_max;
		break;

	case LX_RLIMIT_RTPRIO:
		pd->l_fake_limits[LX_RLFAKE_RTPRIO].rlim_cur = rlim_cur;
		pd->l_fake_limits[LX_RLFAKE_RTPRIO].rlim_max = rlim_max;
		break;

	case LX_RLIMIT_RTTIME:
		pd->l_fake_limits[LX_RLFAKE_RTTIME].rlim_cur = rlim_cur;
		pd->l_fake_limits[LX_RLFAKE_RTTIME].rlim_max = rlim_max;
		break;

	case LX_RLIMIT_RSS:
		/*
		 * zone.max-physical-memory
		 * Since we're emulating the value via a zone rctl, we can't
		 * set that from within the zone. Lie and say we set the value.
		 */
		break;

	case LX_RLIMIT_NPROC:
		/*
		 * zone.max-lwps
		 * Since we're emulating the value via a zone rctl, we can't
		 * set that from within the zone. Lie and say we set the value.
		 */
		break;

	case LX_RLIMIT_MEMLOCK:
		/* Do not exceed zone.max-locked-memory */
		if (rlim_max > curzone->zone_locked_mem_ctl ||
		    rlim_cur > curzone->zone_locked_mem_ctl)
			return (set_errno(EINVAL));

		rl64.rlim_cur = rlim_cur;
		rl64.rlim_max = rlim_max;
		err = lx_set_rctl("process.max-locked-memory", &rl64);
		if (err != 0)
			return (set_errno(err));
		break;

	case LX_RLIMIT_SIGPENDING:
		/*
		 * On Ubuntu at least, the login and sshd processes expect to
		 * set this limit to 16k and login will fail if this fails. On
		 * illumos we have a system limit of 8k and normally the
		 * privileged limit is 512. We simply pretend this works to
		 * allow login to work.
		 */
		if (rlim_max > 8192)
			return (0);

		rl64.rlim_cur = rlim_cur;
		rl64.rlim_max = rlim_max;
		if ((err = lx_set_rctl("process.max-sigqueue-size", &rl64))
		    != 0)
			return (set_errno(err));
		break;

	case LX_RLIMIT_MSGQUEUE:
		rl64.rlim_cur = rlim_cur;
		rl64.rlim_max = rlim_max;
		if ((err = lx_set_rctl("process.max-msg-messages", &rl64)) != 0)
			return (set_errno(err));
		break;

	default:
		resource = l_to_r[lx_resource];

		/*
		 * Linux limits the max number of open files to 1m and there is
		 * a test for this.
		 */
		if (lx_resource == LX_RLIMIT_NOFILE && rlim_max > (1024 * 1024))
			return (EPERM);

		rl64.rlim_cur = rlim_cur;
		rl64.rlim_max = rlim_max;
		gp = rctl_rlimit_set_prealloc(1);

		mutex_enter(&curproc->p_lock);
		err = rctl_rlimit_set(rctlproc_legacy[resource], curproc,
		    &rl64, gp, rctlproc_flags[resource],
		    rctlproc_signals[resource], CRED());
		mutex_exit(&curproc->p_lock);

		rctl_prealloc_destroy(gp);
		if (err != 0)
			return (set_errno(err));
		break;
	}

	return (0);
}

long
lx_setrlimit(int resource, lx_rlimit_t *rlp)
{
	int rv;
	lx_rlimit_t rl;
	uint64_t rlim_cur, rlim_max;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(rlp, &rl, sizeof (rl)) != 0)
			return (set_errno(EFAULT));
	}
#ifdef _SYSCALL32_IMPL
	else {
		lx_rlimit32_t rl32;

		if (copyin(rlp, &rl32, sizeof (rl32)) != 0)
			return (set_errno(EFAULT));

		rl.rlim_cur = rl32.rlim_cur;
		rl.rlim_max = rl32.rlim_max;
	}
#endif

	if ((rl.rlim_max != LX_RLIM_INFINITY_N &&
	    rl.rlim_cur == LX_RLIM_INFINITY_N) ||
	    rl.rlim_cur > rl.rlim_max)
		return (set_errno(EINVAL));

	if (rl.rlim_cur == LX_RLIM_INFINITY_N)
		rlim_cur = LX_RLIM64_INFINITY;
	else
		rlim_cur = rl.rlim_cur;

	if (rl.rlim_max == LX_RLIM_INFINITY_N)
		rlim_max = LX_RLIM64_INFINITY;
	else
		rlim_max = rl.rlim_max;

	rv = lx_setrlimit_common(resource, rlim_cur, rlim_max);
	if (rv != 0)
		return (set_errno(rv));
	return (0);
}

/*
 * From the man page:
 * The Linux-specific prlimit() system call combines and extends the
 * functionality of setrlimit() and getrlimit(). It can be used to both set
 * and get the resource limits of an arbitrary process.
 *
 * If pid is 0, then the call applies to the calling process.
 */
long
lx_prlimit64(pid_t pid, int resource, lx_rlimit64_t *nrlp, lx_rlimit64_t *orlp)
{
	int rv;
	lx_rlimit64_t nrl, orl;

	if (pid != 0) {
		/* XXX TBD if needed */
		char buf[80];

		(void) snprintf(buf, sizeof (buf),
		    "setting prlimit %d for another process\n", resource);
		lx_unsupported(buf);
		return (ENOTSUP);
	}

	if (orlp != NULL) {
		/* we first get the current limits */
		rv = lx_getrlimit_common(resource, &orl.rlim_cur,
		    &orl.rlim_max);
		if (rv != 0)
			return (set_errno(rv));
	}

	if (nrlp != NULL) {
		if (copyin(nrlp, &nrl, sizeof (nrl)) != 0)
			return (set_errno(EFAULT));

		if ((nrl.rlim_max != LX_RLIM64_INFINITY &&
		    nrl.rlim_cur == LX_RLIM64_INFINITY) ||
		    nrl.rlim_cur > nrl.rlim_max)
			return (set_errno(EINVAL));

		rv = lx_setrlimit_common(resource, nrl.rlim_cur, nrl.rlim_max);
		if (rv != 0)
			return (set_errno(rv));
	}

	if (orlp != NULL) {
		/* now return the original limits, if necessary */
		if (copyout(&orl, orlp, sizeof (orl)) != 0)
			return (set_errno(EFAULT));
	}

	return (0);
}
