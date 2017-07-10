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

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/acct.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/session.h>
#include <sys/wait.h>
#include <sys/ddi.h>
#include <sys/zone.h>
#include <sys/lx_types.h>

/*
 * Based on the Linux acct(5) man page, their comp_t definition is the same
 * as ours. lxac_etime is encoded as a float for v3 accounting records.
 */

#define	LX_ACCT_VERSION	3

/*
 * Bit flags in lxac_flag. The Linux AFORK and ASU match native. The rest of
 * the flags diverge.
 */
#define	LX_AFORK	0x01	/* executed fork, but no exec */
#define	LX_ASU		0x02	/* used superuser privileges */
#define	LX_ACORE	0x08	/* dumped core */
#define	LX_AXSIG	0x10	/* killed by a signal */

typedef struct lx_acct {
	char		lxac_flag;
	char		lxac_version;
	uint16_t	lxac_tty;
	uint32_t	lxac_exitcode;
	uint32_t	lxac_uid;
	uint32_t	lxac_gid;
	uint32_t	lxac_pid;
	uint32_t	lxac_ppid;
	uint32_t	lxac_btime;	/* seconds since the epoch */
	uint32_t	lxac_etime;	/* float representation of ticks */
	comp_t		lxac_utime;
	comp_t		lxac_stime;
	comp_t		lxac_mem;	/* kb */
	comp_t		lxac_io;	/* unused */
	comp_t		lxac_rw;	/* unused */
	comp_t		lxac_minflt;
	comp_t		lxac_majflt;
	comp_t		lxac_swaps;	/* unused */
	char		lxac_comm[16];
} lx_acct_t;

/*
 * Same functionality as acct_compress(). Produce a pseudo-floating point
 * representation with 3 bits base-8 exponent, 13 bits fraction.
 */
static comp_t
lx_acct_compt(ulong_t t)
{
	int exp = 0, round = 0;

	while (t >= 8192) {
		exp++;
		round = t & 04;
		t >>= 3;
	}
	if (round) {
		t++;
		if (t >= 8192) {
			t >>= 3;
			exp++;
		}
	}
#ifdef _LP64
	if (exp > 7) {
		/* prevent wraparound */
		t = 8191;
		exp = 7;
	}
#endif
	return ((exp << 13) + t);
}

/*
 * 32-bit IEEE float encoding as-per Linux.
 */
static uint32_t
lx_acct_float(int64_t t)
{
	uint32_t val, exp = 190;

	if (t == 0)
		return (0);

	while (t > 0) {
		t <<= 1;
		exp--;
	}
	val = (uint32_t)(t >> 40) & 0x7fffffu;

	return (val | (exp << 23));
}

/*
 * Write a Linux-formatted record to the accounting file.
 */
void
lx_acct_out(vnode_t *vp, int exit_status)
{
	struct proc *p;
	user_t *ua;
	struct cred *cr;
	dev_t d;
	pid_t pid, ppid;
	struct vattr va;
	ssize_t resid = 0;
	int err;
	lx_acct_t a;

	p = curproc;
	ua = PTOU(p);
	cr = CRED();

	bzero(&a, sizeof (a));

	a.lxac_flag = ua->u_acflag & (LX_AFORK | LX_ASU);
	a.lxac_version = LX_ACCT_VERSION;
	d = cttydev(p);
	a.lxac_tty = LX_MAKEDEVICE(getmajor(d), getminor(d));
	if (WIFEXITED(exit_status)) {
		a.lxac_exitcode = WEXITSTATUS(exit_status);
	} else if (WIFSIGNALED(exit_status)) {
		a.lxac_flag |= LX_AXSIG;
		if (WCOREDUMP(exit_status)) {
			a.lxac_flag |= LX_ACORE;
		}
	}
	a.lxac_uid = crgetruid(cr);
	a.lxac_gid = crgetrgid(cr);
	pid = p->p_pid;
	ppid = p->p_ppid;
	/* Perform pid translation ala lxpr_fixpid(). */
	if (pid == curzone->zone_proc_initpid) {
		pid = 1;
		ppid = 0;
	} else {
		if (ppid == curzone->zone_proc_initpid) {
			ppid = 1;
		} else if (ppid == curzone->zone_zsched->p_pid ||
		    (p->p_flag & SZONETOP) != 0) {
			ppid = 1;
		}
	}
	a.lxac_pid = pid;
	a.lxac_ppid = ppid;
	a.lxac_btime = ua->u_start.tv_sec;
	/* For Linux v3 accounting record, this is an encoded float. */
	a.lxac_etime = lx_acct_float(ddi_get_lbolt() - ua->u_ticks);
	a.lxac_utime = lx_acct_compt(NSEC_TO_TICK(p->p_acct[LMS_USER]));
	a.lxac_stime = lx_acct_compt(
	    NSEC_TO_TICK(p->p_acct[LMS_SYSTEM] + p->p_acct[LMS_TRAP]));
	a.lxac_mem = lx_acct_compt((ulong_t)(ptob(ua->u_mem) / 1024));
	/* a.lxac_io		unused */
	/* a.lxac_rw		unused */
	a.lxac_minflt = lx_acct_compt((ulong_t)p->p_ru.minflt);
	a.lxac_majflt = lx_acct_compt((ulong_t)p->p_ru.majflt);
	/* a.lxac_swaps		unused */
	bcopy(ua->u_comm, a.lxac_comm, sizeof (a.lxac_comm));

	/*
	 * As with the native acct() handling, we save the size so that if the
	 * write fails, we can reset the size to avoid corrupting the accounting
	 * file.
	 */
	va.va_mask = AT_SIZE;
	if (VOP_GETATTR(vp, &va, 0, kcred, NULL) == 0) {
		err = vn_rdwr(UIO_WRITE, vp, (caddr_t)&a, sizeof (a), 0LL,
		    UIO_SYSSPACE, FAPPEND, (rlim64_t)MAXOFF_T, kcred, &resid);
		if (err != 0 || resid != 0)
			(void) VOP_SETATTR(vp, &va, 0, kcred, NULL);
	}
}
