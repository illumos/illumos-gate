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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/systm.h>
#include <sys/sysconfig.h>
#include <rctl.h>
#include <limits.h>
#include <sys/lx_types.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

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

typedef struct {
	ulong_t	rlim_cur;
	ulong_t	rlim_max;
} lx_rlimit_t;

typedef struct {
	uint64_t	rlim_cur;
	uint64_t	rlim_max;
} lx_rlimit64_t;

/*
 * Linux supports many of the same resources that we do, but on Illumos some
 * are rctls. Instead of using rlimit, we use rctls for all of the limits.
 * This table is used to translate Linux resource limit keys into the Illumos
 * rctl.
 */
static char *l_to_rctl[LX_RLIMIT_NLIMITS] = {
	"process.max-cpu-time",		/* 0 CPU */
	"process.max-file-size",	/* 1 FSIZE */
	"process.max-data-size",	/* 2 DATA */
	"process.max-stack-size",	/* 3 STACK */
	"process.max-core-size",	/* 4 CORE */
	"zone.max-physical-memory",	/* 5 RSS */
	"zone.max-lwps",		/* 6 NPROC */
	"process.max-file-descriptor",	/* 7 NOFILE */
	"zone.max-locked-memory",	/* 8 MEMLOCK */
	"process.max-address-space",	/* 9 AS */
	NULL,				/* 10 LOCKS */
	"process.max-sigqueue-size",	/* 11 SIGPENDING */
	"process.max-msg-messages",	/* 12 MSGQUEUE */
	NULL,				/* 13 NICE */
	NULL,				/* 14 RTPRIO */
	NULL				/* 15 RTTIME */
};

/*
 * Magic values Linux uses to indicate infinity
 */
#define	LX_RLIM_INFINITY_O	(0x7fffffffUL)
#define	LX_RLIM_INFINITY_N	ULONG_MAX
#define	LX_RLIM64_INFINITY	(~0ULL)

#define	BIG_INFINITY_O		(0x7fffffffLL)
#define	BIG_INFINITY_N		ULONG_MAX

/*
 * Array to store the rlimits that we track but do not enforce.
 */
static lx_rlimit64_t fake_limits[LX_RLIMIT_NLIMITS] = {
	0, 0,					/* 0 CPU */
	0, 0,					/* 1 FSIZE */
	0, 0,					/* 2 DATA */
	0, 0,					/* 3 STACK */
	0, 0,					/* 4 CORE */
	0, 0,					/* 5 RSS */
	0, 0,					/* 6 NPROC */
	0, 0,					/* 7 NOFILE */
	0, 0,					/* 8 MEMLOCK */
	0, 0,					/* 9 AS */
	LX_RLIM64_INFINITY, LX_RLIM64_INFINITY,	/* 10 LOCKS */
	0, 0,					/* 11 SIGPENDING */
	0, 0,					/* 12 MSGQUEUE */
	20, 20,					/* 13 NICE */
	LX_RLIM64_INFINITY, LX_RLIM64_INFINITY,	/* 14 RTPRIO */
	LX_RLIM64_INFINITY, LX_RLIM64_INFINITY	/* 15 RTTIME */
};

static int
getrlimit_common(int resource, uint64_t *rlim_curp, uint64_t *rlim_maxp)
{
	char *rctl;
	rctlblk_t *rblk;
	int64_t cur = -1;
	boolean_t cur_inf = B_FALSE;
	int64_t max = -1;
	boolean_t max_inf = B_FALSE;

	if (resource < 0 || resource >= LX_RLIMIT_NLIMITS)
		return (-EINVAL);

	rctl = l_to_rctl[resource];
	if (rctl == NULL) {
		switch (resource) {
		case LX_RLIMIT_LOCKS:
		case LX_RLIMIT_NICE:
		case LX_RLIMIT_RTPRIO:
		case LX_RLIMIT_RTTIME:
			*rlim_maxp = fake_limits[resource].rlim_max;
			*rlim_curp = fake_limits[resource].rlim_cur;
			return (0);
		default:
			lx_unsupported("Unsupported resource type %d\n",
			    resource);
			return (-ENOTSUP);
		}
	}

	/*
	 * The brand library cannot use malloc(3C) so we allocate the space
	 * with SAFE_ALLOCA(). Thus there's no need to free it when we're done.
	 */
	rblk = (rctlblk_t *)SAFE_ALLOCA(rctlblk_size());

	if (getrctl(rctl, NULL, rblk, RCTL_FIRST) == -1)
		return (-errno);

	do {
		switch (rctlblk_get_privilege(rblk)) {
		case RCPRIV_BASIC:
			cur = rctlblk_get_value(rblk);
			if (rctlblk_get_local_flags(rblk) &
			    RCTL_LOCAL_MAXIMAL &&
			    rctlblk_get_global_flags(rblk) &
			    RCTL_GLOBAL_INFINITE)
				cur_inf = B_TRUE;
			break;
		case RCPRIV_PRIVILEGED:
			max = rctlblk_get_value(rblk);
			if (rctlblk_get_local_flags(rblk) &
			    RCTL_LOCAL_MAXIMAL &&
			    rctlblk_get_global_flags(rblk) &
			    RCTL_GLOBAL_INFINITE)
				max_inf = B_TRUE;
			break;
		}
	} while (getrctl(rctl, rblk, rblk, RCTL_NEXT) != -1);

	/* Confirm we got values. For many rctls "basic" is not set. */
	if (max == -1)
		max = LX_RLIM64_INFINITY;
	if (cur == -1)
		cur = max;

	if (resource == LX_RLIMIT_STACK && cur > LX_RLIM_INFINITY_O) {
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

	if (cur_inf)
		*rlim_curp = LX_RLIM64_INFINITY;
	else
		*rlim_curp = cur;

	if (max_inf)
		*rlim_maxp = LX_RLIM64_INFINITY;
	else
		*rlim_maxp = max;

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
lx_getrlimit(uintptr_t p1, uintptr_t p2)
{
	int resource = (int)p1;
	lx_rlimit_t *rlp = (lx_rlimit_t *)p2;
	int rv;
	lx_rlimit_t rl;
	uint64_t rlim_cur, rlim_max;

	rv = getrlimit_common(resource, &rlim_cur, &rlim_max);
	if (rv != 0)
		return (rv);

	if (rlim_cur == LX_RLIM64_INFINITY)
		rl.rlim_cur = LX_RLIM_INFINITY_N;
	else if (rlim_cur > BIG_INFINITY_N)
		rl.rlim_cur = LX_RLIM_INFINITY_N;
	else
		rl.rlim_cur = (ulong_t)rlim_cur;

	if (rlim_max == LX_RLIM64_INFINITY)
		rl.rlim_max = LX_RLIM_INFINITY_N;
	else if (rlim_max > BIG_INFINITY_N)
		rl.rlim_max = LX_RLIM_INFINITY_N;
	else
		rl.rlim_max = (ulong_t)rlim_max;

	if ((uucopy(&rl, rlp, sizeof (rl))) != 0)
		return (-errno);

	return (0);
}

/*
 * This is the 'old' getrlimit, variously called getrlimit or old_getrlimit
 * in Linux headers and code.  The only difference between this and the new
 * getrlimit (variously called getrlimit or ugetrlimit) is the value of
 * RLIM_INFINITY, which is smaller for the older version.
 */
long
lx_oldgetrlimit(uintptr_t p1, uintptr_t p2)
{
	int resource = (int)p1;
	lx_rlimit_t *rlp = (lx_rlimit_t *)p2;
	int rv;
	lx_rlimit_t rl;
	uint64_t rlim_cur, rlim_max;

	rv = getrlimit_common(resource, &rlim_cur, &rlim_max);
	if (rv != 0)
		return (rv);

	if (rlim_cur == LX_RLIM64_INFINITY)
		rl.rlim_cur = LX_RLIM_INFINITY_O;
	else if (rlim_cur > BIG_INFINITY_O)
		rl.rlim_cur = LX_RLIM_INFINITY_O;
	else
		rl.rlim_cur = (ulong_t)rlim_cur;

	if (rlim_max == LX_RLIM64_INFINITY)
		rl.rlim_max = LX_RLIM_INFINITY_O;
	else if (rlim_max > BIG_INFINITY_O)
		rl.rlim_max = LX_RLIM_INFINITY_O;
	else
		rl.rlim_max = (ulong_t)rlim_max;

	if ((uucopy(&rl, rlp, sizeof (rl))) != 0)
		return (-errno);

	return (0);
}

static uint64_t
get_rctl_max(char *rctl)
{
	rctlblk_t *rblk;
	uint64_t inf;

	/*
	 * The brand library cannot use malloc(3C) so we allocate the space
	 * with SAFE_ALLOCA(). Thus there's no need to free it when we're done.
	 */
	rblk = (rctlblk_t *)SAFE_ALLOCA(rctlblk_size());

	if (getrctl(rctl, NULL, rblk, RCTL_FIRST) == -1)
		return (-errno);

	do {
		switch (rctlblk_get_privilege(rblk)) {
		case RCPRIV_BASIC:
		case RCPRIV_PRIVILEGED:
			inf = rctlblk_get_value(rblk);
			if (rctlblk_get_local_flags(rblk) &
			    RCTL_LOCAL_MAXIMAL &&
			    rctlblk_get_global_flags(rblk) &
			    RCTL_GLOBAL_INFINITE)
				return (inf);
			break;

		case RCPRIV_SYSTEM:
			inf = rctlblk_get_value(rblk);
			return (inf);
			break;
		}
	} while (getrctl(rctl, rblk, rblk, RCTL_NEXT) != -1);

	/* Somehow we have no max, use the Linux infinite value */
	return (LX_RLIM64_INFINITY);
}

static int
set_rctl(char *rctl, uint64_t value, rctl_priv_t priv)
{
	rctlblk_t *oblk, *nblk;
	boolean_t priv_deny = B_FALSE;
	int priv_sig = 0;

	if (value == LX_RLIM64_INFINITY)
		value = get_rctl_max(rctl);

	/*
	 * The brand library cannot use malloc(3C) so we allocate the space
	 * with SAFE_ALLOCA(). Thus there's no need to free it when we're done.
	 */
	oblk = (rctlblk_t *)SAFE_ALLOCA(rctlblk_size());
	nblk = (rctlblk_t *)SAFE_ALLOCA(rctlblk_size());

	if (getrctl(rctl, NULL, oblk, RCTL_FIRST) == -1)
		return (-errno);

	do {
		if (rctlblk_get_privilege(oblk) == RCPRIV_PRIVILEGED &&
		    rctlblk_get_local_action(oblk, &priv_sig) & RCTL_LOCAL_DENY)
			priv_deny = B_TRUE;

		if (rctlblk_get_privilege(oblk) != priv)
			continue;

		/* we're already at this value, nothing to do */
		if (rctlblk_get_value(oblk) == value)
			return (0);

		/* non-root cannot raise privileged limit */
		if (priv == RCPRIV_PRIVILEGED && geteuid() != 0 &&
		    value > rctlblk_get_value(oblk))
			return (-EPERM);

		bcopy(oblk, nblk, rctlblk_size());
		rctlblk_set_value(nblk, value);
		if (setrctl(rctl, oblk, nblk, RCTL_REPLACE) == -1)
			return (-errno);
		return (0);
	} while (getrctl(rctl, oblk, oblk, RCTL_NEXT) != -1);

	/* not there, add it */
	bzero(nblk, rctlblk_size());
	rctlblk_set_value(nblk, value);
	rctlblk_set_privilege(nblk, priv);
	if (priv_deny) {
		rctlblk_set_local_action(nblk, RCTL_LOCAL_DENY, 0);
	} else {
		rctlblk_set_local_action(nblk, RCTL_LOCAL_SIGNAL, priv_sig);
	}

	if (setrctl(rctl, NULL, nblk, RCTL_INSERT) == -1)
		return (-errno);

	return (0);
}

static int
setrlimit_common(int resource, uint64_t rlim_cur, uint64_t rlim_max)
{
	int rv;
	char *rctl;

	if (resource < 0 || resource >= LX_RLIMIT_NLIMITS)
		return (-EINVAL);

	rctl = l_to_rctl[resource];
	if (rctl == NULL) {
		switch (resource) {
		case LX_RLIMIT_LOCKS:
		case LX_RLIMIT_NICE:
		case LX_RLIMIT_RTPRIO:
		case LX_RLIMIT_RTTIME:
			fake_limits[resource].rlim_max = rlim_max;
			fake_limits[resource].rlim_cur = rlim_cur;
			return (0);
		}

		lx_unsupported("Unsupported resource type %d\n", resource);
		return (-ENOTSUP);
	}

	/*
	 * If we're emulating the value via a zone rctl, we can't set that
	 * from within the zone. Lie and say we set the value.
	 */
	if (strncmp(rctl, "zone.", 5) == 0)
		return (0);

	/*
	 * On Ubuntu at least, the login and sshd processes expect to set this
	 * limit to 16k and login will fail if this fails. On Illumos we have a
	 * system limit of 8k and normally the privileged limit is 512. We
	 * simply pretend this works to allow login to work.
	 */
	if (strcmp(rctl, "process.max-sigqueue-size") == 0 && rlim_max > 8192)
		return (0);

	/*
	 * Linux limits the max number of open files to 1m and there is a test
	 * for this.
	 */
	if (resource == LX_RLIMIT_NOFILE && rlim_max > (1024 * 1024))
		return (-EPERM);

	if ((rv = set_rctl(rctl, rlim_max, RCPRIV_PRIVILEGED)) != 0)
		return (rv);

	return (set_rctl(rctl, rlim_cur, RCPRIV_BASIC));
}

long
lx_setrlimit(uintptr_t p1, uintptr_t p2)
{
	int resource = (int)p1;
	lx_rlimit_t rl;
	uint64_t rlim_cur, rlim_max;

	if (uucopy((void *)p2, &rl, sizeof (rl)) != 0)
		return (-errno);

	if ((rl.rlim_max != LX_RLIM_INFINITY_N &&
	    rl.rlim_cur == LX_RLIM_INFINITY_N) ||
	    rl.rlim_cur > rl.rlim_max)
		return (-EINVAL);

	if (rl.rlim_cur == LX_RLIM_INFINITY_N)
		rlim_cur = LX_RLIM64_INFINITY;
	else
		rlim_cur = rl.rlim_cur;

	if (rl.rlim_max == LX_RLIM_INFINITY_N)
		rlim_max = LX_RLIM64_INFINITY;
	else
		rlim_max = rl.rlim_max;

	return (setrlimit_common(resource, rlim_cur, rlim_max));
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
lx_prlimit64(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	pid_t pid = (pid_t)p1;
	int resource = (int)p2;
	lx_rlimit64_t *nrlp = (lx_rlimit64_t *)p3;
	lx_rlimit64_t *orlp = (lx_rlimit64_t *)p4;
	int rv = 0;
	uint64_t rlim_cur, rlim_max;
	lx_rlimit64_t nrl, orl;

	if (pid != 0) {
		/* XXX TBD if needed */
		lx_unsupported("setting prlimit %d for another process\n",
		    resource);
		return (-ENOTSUP);
	}

	if (orlp != NULL) {
		/* we first get the current limits */
		rv = getrlimit_common(resource, &rlim_cur, &rlim_max);
		if (rv != 0)
			return (rv);
	}

	if (nrlp != NULL) {
		if (uucopy((void *)p3, &nrl, sizeof (nrl)) != 0)
			return (-errno);

		if ((nrl.rlim_max != LX_RLIM64_INFINITY &&
		    nrl.rlim_cur == LX_RLIM64_INFINITY) ||
		    nrl.rlim_cur > nrl.rlim_max)
			return (-EINVAL);

		rv = setrlimit_common(resource, nrl.rlim_cur, nrl.rlim_max);
	}

	if (rv == 0 && orlp != NULL) {
		/* now return the original limits, if necessary */
		orl.rlim_cur = rlim_cur;
		orl.rlim_max = rlim_max;

		if ((uucopy(&orl, orlp, sizeof (orl))) != 0)
			rv = -errno;
	}

	return (rv);
}

/*
 * We lucked out here.  Linux and Solaris have exactly the same
 * rusage structures.
 */
long
lx_getrusage(uintptr_t p1, uintptr_t p2)
{
	int who = (int)p1;
	struct rusage *rup = (struct rusage *)p2;
	int rv, swho;

	if (who == LX_RUSAGE_SELF)
		swho = RUSAGE_SELF;
	else if (who == LX_RUSAGE_CHILDREN)
		swho = RUSAGE_CHILDREN;
	else if (who == LX_RUSAGE_THREAD)
		swho = RUSAGE_LWP;
	else
		return (-EINVAL);

	rv = getrusage(swho, rup);

	return (rv < 0 ? -errno : 0);
}
