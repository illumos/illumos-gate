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
 * Copyright 2018 Joyent, Inc.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2023 Oxide Computer Company
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
 * information from either a live process or core file opened with libproc.  We
 * build up a few common routines for reading and writing register information,
 * and then the public functions are all trivial calls to these.  It also
 * implements similar logic that is used with an lwp handle.
 *
 * The primary registers and floating point registers (e.g. regs,fpregs) are
 * retreived from the lwp and process status files.  The library caches the
 * values of these files.  When we perorm updates, we ensure that cached copies
 * are refreshed or updated as part of this.
 */

/*
 * Utility function to return a pointer to the structure of cached information
 * about an lwp in the core file, given its lwpid.
 */
static lwp_info_t *
getlwpcore(struct ps_prochandle *P, lwpid_t lwpid)
{
	core_info_t *core = P->data;
	lwp_info_t *lwp;

	for (lwp = list_head(&core->core_lwp_head); lwp != NULL;
	    lwp = list_next(&core->core_lwp_head, lwp)) {
		if (lwp->lwp_id == lwpid)
			return (lwp);
	}

	errno = ENOENT;
	return (NULL);
}

/*
 * Utility function to open and read the contents of a per-lwp /proc file.
 * This function is used to slurp in lwpstatus, lwpname, lwpsinfo, spymaster,
 * and others.
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

		int e = errno;
		(void) close(fd);
		errno = e;
	}
	return (-1);
}

/*
 * This is a variant of getlwpfile that has three different semantics:
 *
 *  o It will stat the file to determine the size and allocate that for the
 *    caller.
 *  o If the stat size is zero (e.g. traditional xregs behavior when
 *    unsupported) then it will return the libproc ENODATA error.
 *  o It is an error if not all the data is read.
 *
 * Currently this is just used by xregs.
 */
static int
getlwpfile_alloc(struct ps_prochandle *P, lwpid_t lwpid, const char *fbase,
    void **datap, size_t *sizep)
{
	char fname[PATH_MAX];
	int fd;

	(void) snprintf(fname, sizeof (fname), "%s/%d/lwp/%d/%s",
	    procfs_path, (int)P->status.pr_pid, (int)lwpid, fbase);

	if ((fd = open(fname, O_RDONLY)) >= 0) {
		int e;
		struct stat st;

		if (fstat(fd, &st) == 0) {
			prxregset_t *prx;

			if (st.st_size == 0) {
				errno = ENODATA;
				goto clean;
			}

			prx = malloc(st.st_size);
			if (prx == NULL) {
				goto clean;
			}

			if (read(fd, prx, st.st_size) == st.st_size) {
				(void) close(fd);
				*datap = prx;
				*sizep = st.st_size;
				return (0);
			}

			free(prx);
		}
clean:
		e = errno;
		(void) close(fd);
		errno = e;
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
 * libproc caches information about the registers for representative LWPs and
 * threads which we have the thread handle for. When we do a write to certain
 * files, we need to refresh state and take care of both the process and the
 * representative LWP's info. Because the xregs may or may not mutate the state
 * of the other regsiters, we just always do a refresh of the entire cached
 * psinfo.
 */
static void
refresh_status(struct ps_prochandle *P, lwpid_t lwpid, struct ps_lwphandle *L,
    long cmd, const void *rp, size_t n)
{
	if (P->status.pr_lwp.pr_lwpid == lwpid) {
		if (cmd == PCSREG)
			(void) memcpy(P->status.pr_lwp.pr_reg, rp, n);
		else if (cmd == PCSFPREG)
			(void) memcpy(&P->status.pr_lwp.pr_fpreg, rp, n);
		else if (cmd == PCSXREG)
			(void) Pstopstatus(P, PCNULL, 0);
	}

	if (L != NULL) {
		if (cmd == PCSREG)
			(void) memcpy(&L->lwp_status.pr_reg, rp, n);
		else if (cmd == PCSFPREG)
			(void) memcpy(&L->lwp_status.pr_fpreg, rp, n);
		else if (cmd == PCSXREG)
			(void) Lstopstatus(L, PCNULL, 0);
	}
}

/*
 * Utility function to modify lwp registers.  This is done using either the
 * process control file or per-lwp control file as necessary.  This assumes that
 * we have a process-level hold on things, which may not always be true.
 */
static int
setlwpregs_proc(struct ps_prochandle *P, lwpid_t lwpid, long cmd,
    const void *rp, size_t n)
{
	iovec_t iov[2];
	char fname[PATH_MAX];
	struct ps_lwphandle *L;
	int fd = -1;

	if (P->state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	iov[0].iov_base = (caddr_t)&cmd;
	iov[0].iov_len = sizeof (long);
	iov[1].iov_base = (caddr_t)rp;
	iov[1].iov_len = n;

	/*
	 * If we have an lwp handle for this thread, then make sure that we use
	 * that to update the state so cached information is updated.  We sync
	 * the thread ahead of the process.
	 */
	if ((L = Lfind(P, lwpid)) != NULL) {
		Lsync(L);
		fd = L->lwp_ctlfd;
	}

	/*
	 * Writing the process control file writes the representative lwp.
	 * Psync before we write to make sure we are consistent with the
	 * primary interfaces.  Similarly, make sure to update P->status
	 * afterward if we are modifying one of its register sets.  On some
	 * platforms the xregs cover the base integer or floating point
	 * registers.  As a result, always refresh the representative LWP's
	 * status.
	 */
	if (P->status.pr_lwp.pr_lwpid == lwpid) {
		Psync(P);
		fd = P->ctlfd;
	}

	if (fd > -1) {
		if (writev(fd, iov, 2) == -1)
			return (-1);
		refresh_status(P, lwpid, L, cmd, rp, n);
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
		int e = errno;
		(void) close(fd);
		errno = e;
	}
	return (-1);
}

/*
 * This is a variant of the above that only assumes we have a hold on the thread
 * as opposed to a process.
 */
static int
setlwpregs_lwp(struct ps_lwphandle *L, long cmd, const void *rp, size_t n)
{
	iovec_t iov[2];

	if (L->lwp_state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	iov[0].iov_base = (caddr_t)&cmd;
	iov[0].iov_len = sizeof (long);
	iov[1].iov_base = (caddr_t)rp;
	iov[1].iov_len = n;

	Lsync(L);
	if (writev(L->lwp_ctlfd, iov, 2) == -1)
		return (-1);
	refresh_status(L->lwp_proc, L->lwp_id, L, cmd, rp, n);

	return (0);
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
Lgetregs(struct ps_lwphandle *L, prgregset_t *gregs)
{
	(void) memcpy(gregs, L->lwp_status.pr_reg, sizeof (prgregset_t));
	return (0);
}

int
Plwp_setregs(struct ps_prochandle *P, lwpid_t lwpid, const prgregset_t gregs)
{
	return (setlwpregs_proc(P, lwpid, PCSREG, gregs, sizeof (prgregset_t)));
}

int
Lsetregs(struct ps_lwphandle *L, const prgregset_t *gregs)
{
	return (setlwpregs_lwp(L, PCSREG, gregs, sizeof (prgregset_t)));
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

int
Lgetfpregs(struct ps_lwphandle *L, prfpregset_t *fpregs)
{
	(void) memcpy(fpregs, &L->lwp_status.pr_fpreg, sizeof (prfpregset_t));
	return (0);
}

int
Plwp_setfpregs(struct ps_prochandle *P, lwpid_t lwpid,
    const prfpregset_t *fpregs)
{
	return (setlwpregs_proc(P, lwpid, PCSFPREG, fpregs,
	    sizeof (prfpregset_t)));
}

int
Lsetfpregs(struct ps_lwphandle *L, const prfpregset_t *fpregs)
{
	return (setlwpregs_lwp(L, PCSFPREG, fpregs, sizeof (prfpregset_t)));
}

/*
 * The reason that this is structured to take both the size and the process
 * handle is so that way we have enough information to tie this back to its
 * underlying source and we can eventually use umem with this.
 */
void
Plwp_freexregs(struct ps_prochandle *P __unused, prxregset_t *prx,
    size_t size __unused)
{
	free(prx);
}

/*
 * Get a given thread's lwp registers. If this is a core file, we read it from
 * the cache. If this is a live process, we always read it from the underlying
 * file system because we do not currently cache xregs in libproc. sizep is the
 * resulting size of data we've allocated and for a live process is filled in
 * based on the /proc stat(2) information.
 */
int
Plwp_getxregs(struct ps_prochandle *P, lwpid_t lwpid, prxregset_t **xregs,
    size_t *sizep)
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

		return (getlwpfile_alloc(P, lwpid, "xregs",
		    (void **)xregs, sizep));
	}

	if ((lwp = getlwpcore(P, lwpid)) != NULL && lwp->lwp_xregs != NULL &&
	    lwp->lwp_xregsize > 0) {
		*xregs = malloc(lwp->lwp_xregsize);
		if (*xregs == NULL)
			return (-1);
		(void) memcpy(*xregs, lwp->lwp_xregs, lwp->lwp_xregsize);
		*sizep = lwp->lwp_xregsize;
		return (0);
	}

	if (lwp != NULL)
		errno = ENODATA;
	return (-1);
}

int
Lgetxregs(struct ps_lwphandle *L, prxregset_t **xregs, size_t *sizep)
{
	lwp_info_t *lwp;

	if (L->lwp_state != PS_DEAD) {
		if (L->lwp_state != PS_STOP) {
			errno = EBUSY;
			return (-1);
		}
		return (getlwpfile_alloc(L->lwp_proc, L->lwp_id, "xregs",
		    (void **)xregs, sizep));
	}

	if ((lwp = getlwpcore(L->lwp_proc, L->lwp_id)) != NULL &&
	    lwp->lwp_xregs != NULL && lwp->lwp_xregsize > 0) {
		*xregs = malloc(lwp->lwp_xregsize);
		if (*xregs == NULL)
			return (-1);
		(void) memcpy(*xregs, lwp->lwp_xregs, lwp->lwp_xregsize);
		*sizep = lwp->lwp_xregsize;
		return (0);
	}

	if (lwp != NULL)
		errno = ENODATA;
	return (-1);
}

int
Plwp_setxregs(struct ps_prochandle *P, lwpid_t lwpid, const prxregset_t *xregs,
    size_t len)
{
	return (setlwpregs_proc(P, lwpid, PCSXREG, xregs, len));
}

int
Lsetxregs(struct ps_lwphandle *L, const prxregset_t *xregs, size_t len)
{
	return (setlwpregs_lwp(L, PCSXREG, xregs, len));
}

#if defined(sparc) || defined(__sparc)
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
	return (setlwpregs_proc(P, lwpid, PCSASRS, asrs, sizeof (asrset_t)));
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
Plwp_getname(struct ps_prochandle *P, lwpid_t lwpid,
    char *buf, size_t bufsize)
{
	char lwpname[THREAD_NAME_MAX];
	char *from = NULL;
	lwp_info_t *lwp;

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_DEAD) {
		if (getlwpfile(P, lwpid, "lwpname",
		    lwpname, sizeof (lwpname)) != 0)
			return (-1);
		from = lwpname;
	} else {
		if ((lwp = getlwpcore(P, lwpid)) == NULL)
			return (-1);
		from = lwp->lwp_name;
	}

	if (strlcpy(buf, from, bufsize) >= bufsize) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (0);
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
