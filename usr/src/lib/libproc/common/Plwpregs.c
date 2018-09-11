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
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "Pcontrol.h"
#include "P32ton.h"

/*
 * This file implements the routines to read and write per-lwp register
 * information from either a live process or core file opened with libproc.
 * We build up a few common routines for reading and writing register
 * information, and then the public functions are all trivial calls to these.
 */

/*
 * Utility function to return a pointer to the structure of cached information
 * about an lwp in the core file, given its lwpid.
 */
static lwp_info_t *
getlwpcore(struct ps_prochandle *P, lwpid_t lwpid)
{
	core_info_t *core = P->data;
	lwp_info_t *lwp = list_next(&core->core_lwp_head);
	uint_t i;

	for (i = 0; i < core->core_nlwp; i++, lwp = list_next(lwp)) {
		if (lwp->lwp_id == lwpid)
			return (lwp);
	}

	errno = EINVAL;
	return (NULL);
}

/*
 * Utility function to open and read the contents of a per-lwp /proc file.
 * This function is used to slurp in lwpstatus, xregs, and asrs.
 */
static int
getlwpfile(struct ps_prochandle *P, lwpid_t lwpid,
    const char *fbase, void *rp, size_t n)
{
	char fname[PATH_MAX];
	int fd;

	(void) snprintf(fname, sizeof (fname), "%s/%d/lwp/%d/%s",
	    procfs_path, (int)P->status.pr_pid, (int)lwpid, fbase);

	if ((fd = open(fname, O_RDONLY)) >= 0) {
		if (read(fd, rp, n) > 0) {
			(void) close(fd);
			return (0);
		}
		(void) close(fd);
	}
	return (-1);
}

/*
 * Get the lwpstatus_t for an lwp from either the live process or our
 * cached information from the core file.  This is used to get the
 * general-purpose registers or floating point registers.
 */
int
getlwpstatus(struct ps_prochandle *P, lwpid_t lwpid, lwpstatus_t *lps)
{
	lwp_info_t *lwp;

	/*
	 * For both live processes and cores, our job is easy if the lwpid
	 * matches that of the representative lwp:
	 */
	if (P->status.pr_lwp.pr_lwpid == lwpid) {
		(void) memcpy(lps, &P->status.pr_lwp, sizeof (lwpstatus_t));
		return (0);
	}

	/*
	 * If this is a live process, then just read the information out
	 * of the per-lwp status file:
	 */
	if (P->state != PS_DEAD) {
		return (getlwpfile(P, lwpid, "lwpstatus",
		    lps, sizeof (lwpstatus_t)));
	}

	/*
	 * If this is a core file, we need to iterate through our list of
	 * cached lwp information and then copy out the status.
	 */
	if (P->data != NULL && (lwp = getlwpcore(P, lwpid)) != NULL) {
		(void) memcpy(lps, &lwp->lwp_status, sizeof (lwpstatus_t));
		return (0);
	}

	return (-1);
}

/*
 * Utility function to modify lwp registers.  This is done using either the
 * process control file or per-lwp control file as necessary.
 */
static int
setlwpregs(struct ps_prochandle *P, lwpid_t lwpid, long cmd,
    const void *rp, size_t n)
{
	iovec_t iov[2];
	char fname[PATH_MAX];
	int fd;

	if (P->state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	iov[0].iov_base = (caddr_t)&cmd;
	iov[0].iov_len = sizeof (long);
	iov[1].iov_base = (caddr_t)rp;
	iov[1].iov_len = n;

	/*
	 * Writing the process control file writes the representative lwp.
	 * Psync before we write to make sure we are consistent with the
	 * primary interfaces.  Similarly, make sure to update P->status
	 * afterward if we are modifying one of its register sets.
	 */
	if (P->status.pr_lwp.pr_lwpid == lwpid) {
		Psync(P);

		if (writev(P->ctlfd, iov, 2) == -1)
			return (-1);

		if (cmd == PCSREG)
			(void) memcpy(P->status.pr_lwp.pr_reg, rp, n);
		else if (cmd == PCSFPREG)
			(void) memcpy(&P->status.pr_lwp.pr_fpreg, rp, n);

		return (0);
	}

	/*
	 * If the lwp we want is not the representative lwp, we need to
	 * open the ctl file for that specific lwp.
	 */
	(void) snprintf(fname, sizeof (fname), "%s/%d/lwp/%d/lwpctl",
	    procfs_path, (int)P->status.pr_pid, (int)lwpid);

	if ((fd = open(fname, O_WRONLY)) >= 0) {
		if (writev(fd, iov, 2) > 0) {
			(void) close(fd);
			return (0);
		}
		(void) close(fd);
	}
	return (-1);
}

int
Plwp_getregs(struct ps_prochandle *P, lwpid_t lwpid, prgregset_t gregs)
{
	lwpstatus_t lps;

	if (getlwpstatus(P, lwpid, &lps) == -1)
		return (-1);

	(void) memcpy(gregs, lps.pr_reg, sizeof (prgregset_t));
	return (0);
}

int
Plwp_setregs(struct ps_prochandle *P, lwpid_t lwpid, const prgregset_t gregs)
{
	return (setlwpregs(P, lwpid, PCSREG, gregs, sizeof (prgregset_t)));
}

int
Plwp_getfpregs(struct ps_prochandle *P, lwpid_t lwpid, prfpregset_t *fpregs)
{
	lwpstatus_t lps;

	if (getlwpstatus(P, lwpid, &lps) == -1)
		return (-1);

	(void) memcpy(fpregs, &lps.pr_fpreg, sizeof (prfpregset_t));
	return (0);
}

int Plwp_setfpregs(struct ps_prochandle *P, lwpid_t lwpid,
    const prfpregset_t *fpregs)
{
	return (setlwpregs(P, lwpid, PCSFPREG, fpregs, sizeof (prfpregset_t)));
}

#if defined(sparc) || defined(__sparc)
int
Plwp_getxregs(struct ps_prochandle *P, lwpid_t lwpid, prxregset_t *xregs)
{
	lwp_info_t *lwp;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		if (P->state != PS_STOP) {
			errno = EBUSY;
			return (-1);
		}

		return (getlwpfile(P, lwpid, "xregs",
		    xregs, sizeof (prxregset_t)));
	}

	if ((lwp = getlwpcore(P, lwpid)) != NULL && lwp->lwp_xregs != NULL) {
		(void) memcpy(xregs, lwp->lwp_xregs, sizeof (prxregset_t));
		return (0);
	}

	if (lwp != NULL)
		errno = ENODATA;
	return (-1);
}

int
Plwp_setxregs(struct ps_prochandle *P, lwpid_t lwpid, const prxregset_t *xregs)
{
	return (setlwpregs(P, lwpid, PCSXREG, xregs, sizeof (prxregset_t)));
}

int
Plwp_getgwindows(struct ps_prochandle *P, lwpid_t lwpid, gwindows_t *gwins)
{
	lwp_info_t *lwp;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		if (P->state != PS_STOP) {
			errno = EBUSY;
			return (-1);
		}

		return (getlwpfile(P, lwpid, "gwindows",
		    gwins, sizeof (gwindows_t)));
	}

	if ((lwp = getlwpcore(P, lwpid)) != NULL && lwp->lwp_gwins != NULL) {
		*gwins = *lwp->lwp_gwins;
		return (0);
	}

	if (lwp != NULL)
		errno = ENODATA;
	return (-1);
}

#if defined(__sparcv9)
int
Plwp_getasrs(struct ps_prochandle *P, lwpid_t lwpid, asrset_t asrs)
{
	lwp_info_t *lwp;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		if (P->state != PS_STOP) {
			errno = EBUSY;
			return (-1);
		}

		return (getlwpfile(P, lwpid, "asrs", asrs, sizeof (asrset_t)));
	}

	if ((lwp = getlwpcore(P, lwpid)) != NULL && lwp->lwp_asrs != NULL) {
		(void) memcpy(asrs, lwp->lwp_asrs, sizeof (asrset_t));
		return (0);
	}

	if (lwp != NULL)
		errno = ENODATA;
	return (-1);

}

int
Plwp_setasrs(struct ps_prochandle *P, lwpid_t lwpid, const asrset_t asrs)
{
	return (setlwpregs(P, lwpid, PCSASRS, asrs, sizeof (asrset_t)));
}
#endif	/* __sparcv9 */
#endif	/* __sparc */

int
Plwp_getpsinfo(struct ps_prochandle *P, lwpid_t lwpid, lwpsinfo_t *lps)
{
	lwp_info_t *lwp;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		return (getlwpfile(P, lwpid, "lwpsinfo",
		    lps, sizeof (lwpsinfo_t)));
	}

	if ((lwp = getlwpcore(P, lwpid)) != NULL) {
		(void) memcpy(lps, &lwp->lwp_psinfo, sizeof (lwpsinfo_t));
		return (0);
	}

	return (-1);
}

int
Plwp_getspymaster(struct ps_prochandle *P, lwpid_t lwpid, psinfo_t *ps)
{
	lwpstatus_t lps;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (getlwpstatus(P, lwpid, &lps) != 0)
		return (-1);

	if (!(lps.pr_flags & PR_AGENT)) {
		errno = EINVAL;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		return (getlwpfile(P, lwpid, "spymaster",
		    ps, sizeof (psinfo_t)));
	}

	if (P->spymaster.pr_nlwp != 0) {
		(void) memcpy(ps, &P->spymaster, sizeof (psinfo_t));
		return (0);
	}

	errno = ENODATA;

	return (-1);
}

int
Plwp_stack(struct ps_prochandle *P, lwpid_t lwpid, stack_t *stkp)
{
	uintptr_t addr;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		lwpstatus_t ls;
		if (getlwpfile(P, lwpid, "lwpstatus", &ls, sizeof (ls)) != 0)
			return (-1);
		addr = ls.pr_ustack;
	} else {
		lwp_info_t *lwp;
		if ((lwp = getlwpcore(P, lwpid)) == NULL)
			return (-1);
		addr = lwp->lwp_status.pr_ustack;
	}


	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		if (Pread(P, stkp, sizeof (*stkp), addr) != sizeof (*stkp))
			return (-1);
#ifdef _LP64
	} else {
		stack32_t stk32;

		if (Pread(P, &stk32, sizeof (stk32), addr) != sizeof (stk32))
			return (-1);

		stack_32_to_n(&stk32, stkp);
#endif
	}

	return (0);
}

int
Plwp_main_stack(struct ps_prochandle *P, lwpid_t lwpid, stack_t *stkp)
{
	uintptr_t addr;
	lwpstatus_t ls;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		if (getlwpfile(P, lwpid, "lwpstatus", &ls, sizeof (ls)) != 0)
			return (-1);
	} else {
		lwp_info_t *lwp;
		if ((lwp = getlwpcore(P, lwpid)) == NULL)
			return (-1);
		ls = lwp->lwp_status;
	}

	addr = ls.pr_ustack;

	/*
	 * Read out the current stack; if the SS_ONSTACK flag is set then
	 * this LWP is operating on the alternate signal stack. We can
	 * recover the original stack from pr_oldcontext.
	 */
	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		if (Pread(P, stkp, sizeof (*stkp), addr) != sizeof (*stkp))
			return (-1);

		if (stkp->ss_flags & SS_ONSTACK)
			goto on_altstack;
#ifdef _LP64
	} else {
		stack32_t stk32;

		if (Pread(P, &stk32, sizeof (stk32), addr) != sizeof (stk32))
			return (-1);

		if (stk32.ss_flags & SS_ONSTACK)
			goto on_altstack;

		stack_32_to_n(&stk32, stkp);
#endif
	}

	return (0);

on_altstack:

	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		ucontext_t *ctxp = (void *)ls.pr_oldcontext;

		if (Pread(P, stkp, sizeof (*stkp),
		    (uintptr_t)&ctxp->uc_stack) != sizeof (*stkp))
			return (-1);
#ifdef _LP64
	} else {
		ucontext32_t *ctxp = (void *)ls.pr_oldcontext;
		stack32_t stk32;

		if (Pread(P, &stk32, sizeof (stk32),
		    (uintptr_t)&ctxp->uc_stack) != sizeof (stk32))
			return (-1);

		stack_32_to_n(&stk32, stkp);
#endif
	}

	return (0);
}

int
Plwp_alt_stack(struct ps_prochandle *P, lwpid_t lwpid, stack_t *stkp)
{
	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		lwpstatus_t ls;

		if (getlwpfile(P, lwpid, "lwpstatus", &ls, sizeof (ls)) != 0)
			return (-1);

		if (ls.pr_altstack.ss_flags & SS_DISABLE) {
			errno = ENODATA;
			return (-1);
		}

		*stkp = ls.pr_altstack;
	} else {
		lwp_info_t *lwp;

		if ((lwp = getlwpcore(P, lwpid)) == NULL)
			return (-1);

		if (lwp->lwp_status.pr_altstack.ss_flags & SS_DISABLE) {
			errno = ENODATA;
			return (-1);
		}

		*stkp = lwp->lwp_status.pr_altstack;
	}

	return (0);
}
