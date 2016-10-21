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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2015 Gary Mills
 */

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>

#include <alloca.h>
#include <rtld_db.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <gelf.h>
#include <stddef.h>
#include <signal.h>

#include "libproc.h"
#include "Pcontrol.h"
#include "P32ton.h"
#include "Putil.h"
#ifdef __x86
#include "Pcore_linux.h"
#endif

/*
 * Pcore.c - Code to initialize a ps_prochandle from a core dump.  We
 * allocate an additional structure to hold information from the core
 * file, and attach this to the standard ps_prochandle in place of the
 * ability to examine /proc/<pid>/ files.
 */

/*
 * Basic i/o function for reading and writing from the process address space
 * stored in the core file and associated shared libraries.  We compute the
 * appropriate fd and offsets, and let the provided prw function do the rest.
 */
static ssize_t
core_rw(struct ps_prochandle *P, void *buf, size_t n, uintptr_t addr,
    ssize_t (*prw)(int, void *, size_t, off64_t))
{
	ssize_t resid = n;

	while (resid != 0) {
		map_info_t *mp = Paddr2mptr(P, addr);

		uintptr_t mapoff;
		ssize_t len;
		off64_t off;
		int fd;

		if (mp == NULL)
			break;	/* No mapping for this address */

		if (mp->map_pmap.pr_mflags & MA_RESERVED1) {
			if (mp->map_file == NULL || mp->map_file->file_fd < 0)
				break;	/* No file or file not open */

			fd = mp->map_file->file_fd;
		} else
			fd = P->asfd;

		mapoff = addr - mp->map_pmap.pr_vaddr;
		len = MIN(resid, mp->map_pmap.pr_size - mapoff);
		off = mp->map_offset + mapoff;

		if ((len = prw(fd, buf, len, off)) <= 0)
			break;

		resid -= len;
		addr += len;
		buf = (char *)buf + len;
	}

	/*
	 * Important: Be consistent with the behavior of i/o on the as file:
	 * writing to an invalid address yields EIO; reading from an invalid
	 * address falls through to returning success and zero bytes.
	 */
	if (resid == n && n != 0 && prw != pread64) {
		errno = EIO;
		return (-1);
	}

	return (n - resid);
}

/*ARGSUSED*/
static ssize_t
Pread_core(struct ps_prochandle *P, void *buf, size_t n, uintptr_t addr,
    void *data)
{
	return (core_rw(P, buf, n, addr, pread64));
}

/*ARGSUSED*/
static ssize_t
Pwrite_core(struct ps_prochandle *P, const void *buf, size_t n, uintptr_t addr,
    void *data)
{
	return (core_rw(P, (void *)buf, n, addr,
	    (ssize_t (*)(int, void *, size_t, off64_t)) pwrite64));
}

/*ARGSUSED*/
static int
Pcred_core(struct ps_prochandle *P, prcred_t *pcrp, int ngroups, void *data)
{
	core_info_t *core = data;

	if (core->core_cred != NULL) {
		/*
		 * Avoid returning more supplementary group data than the
		 * caller has allocated in their buffer.  We expect them to
		 * check pr_ngroups afterward and potentially call us again.
		 */
		ngroups = MIN(ngroups, core->core_cred->pr_ngroups);

		(void) memcpy(pcrp, core->core_cred,
		    sizeof (prcred_t) + (ngroups - 1) * sizeof (gid_t));

		return (0);
	}

	errno = ENODATA;
	return (-1);
}

/*ARGSUSED*/
static int
Psecflags_core(struct ps_prochandle *P, prsecflags_t **psf, void *data)
{
	core_info_t *core = data;

	if (core->core_secflags == NULL) {
		errno = ENODATA;
		return (-1);
	}

	if ((*psf = calloc(1, sizeof (prsecflags_t))) == NULL)
		return (-1);

	(void) memcpy(*psf, core->core_secflags, sizeof (prsecflags_t));

	return (0);
}

/*ARGSUSED*/
static int
Ppriv_core(struct ps_prochandle *P, prpriv_t **pprv, void *data)
{
	core_info_t *core = data;

	if (core->core_priv == NULL) {
		errno = ENODATA;
		return (-1);
	}

	*pprv = malloc(core->core_priv_size);
	if (*pprv == NULL) {
		return (-1);
	}

	(void) memcpy(*pprv, core->core_priv, core->core_priv_size);
	return (0);
}

/*ARGSUSED*/
static const psinfo_t *
Ppsinfo_core(struct ps_prochandle *P, psinfo_t *psinfo, void *data)
{
	return (&P->psinfo);
}

/*ARGSUSED*/
static void
Pfini_core(struct ps_prochandle *P, void *data)
{
	core_info_t *core = data;

	if (core != NULL) {
		extern void __priv_free_info(void *);
		lwp_info_t *nlwp, *lwp = list_next(&core->core_lwp_head);
		int i;

		for (i = 0; i < core->core_nlwp; i++, lwp = nlwp) {
			nlwp = list_next(lwp);
#ifdef __sparc
			if (lwp->lwp_gwins != NULL)
				free(lwp->lwp_gwins);
			if (lwp->lwp_xregs != NULL)
				free(lwp->lwp_xregs);
			if (lwp->lwp_asrs != NULL)
				free(lwp->lwp_asrs);
#endif
			free(lwp);
		}

		if (core->core_platform != NULL)
			free(core->core_platform);
		if (core->core_uts != NULL)
			free(core->core_uts);
		if (core->core_cred != NULL)
			free(core->core_cred);
		if (core->core_priv != NULL)
			free(core->core_priv);
		if (core->core_privinfo != NULL)
			__priv_free_info(core->core_privinfo);
		if (core->core_ppii != NULL)
			free(core->core_ppii);
		if (core->core_zonename != NULL)
			free(core->core_zonename);
		if (core->core_secflags != NULL)
			free(core->core_secflags);
#ifdef __x86
		if (core->core_ldt != NULL)
			free(core->core_ldt);
#endif

		free(core);
	}
}

/*ARGSUSED*/
static char *
Pplatform_core(struct ps_prochandle *P, char *s, size_t n, void *data)
{
	core_info_t *core = data;

	if (core->core_platform == NULL) {
		errno = ENODATA;
		return (NULL);
	}
	(void) strncpy(s, core->core_platform, n - 1);
	s[n - 1] = '\0';
	return (s);
}

/*ARGSUSED*/
static int
Puname_core(struct ps_prochandle *P, struct utsname *u, void *data)
{
	core_info_t *core = data;

	if (core->core_uts == NULL) {
		errno = ENODATA;
		return (-1);
	}
	(void) memcpy(u, core->core_uts, sizeof (struct utsname));
	return (0);
}

/*ARGSUSED*/
static char *
Pzonename_core(struct ps_prochandle *P, char *s, size_t n, void *data)
{
	core_info_t *core = data;

	if (core->core_zonename == NULL) {
		errno = ENODATA;
		return (NULL);
	}
	(void) strlcpy(s, core->core_zonename, n);
	return (s);
}

#ifdef __x86
/*ARGSUSED*/
static int
Pldt_core(struct ps_prochandle *P, struct ssd *pldt, int nldt, void *data)
{
	core_info_t *core = data;

	if (pldt == NULL || nldt == 0)
		return (core->core_nldt);

	if (core->core_ldt != NULL) {
		nldt = MIN(nldt, core->core_nldt);

		(void) memcpy(pldt, core->core_ldt,
		    nldt * sizeof (struct ssd));

		return (nldt);
	}

	errno = ENODATA;
	return (-1);
}
#endif

static const ps_ops_t P_core_ops = {
	.pop_pread	= Pread_core,
	.pop_pwrite	= Pwrite_core,
	.pop_cred	= Pcred_core,
	.pop_priv	= Ppriv_core,
	.pop_psinfo	= Ppsinfo_core,
	.pop_fini	= Pfini_core,
	.pop_platform	= Pplatform_core,
	.pop_uname	= Puname_core,
	.pop_zonename	= Pzonename_core,
	.pop_secflags	= Psecflags_core,
#ifdef __x86
	.pop_ldt	= Pldt_core
#endif
};

/*
 * Return the lwp_info_t for the given lwpid.  If no such lwpid has been
 * encountered yet, allocate a new structure and return a pointer to it.
 * Create a list of lwp_info_t structures sorted in decreasing lwp_id order.
 */
static lwp_info_t *
lwpid2info(struct ps_prochandle *P, lwpid_t id)
{
	core_info_t *core = P->data;
	lwp_info_t *lwp = list_next(&core->core_lwp_head);
	lwp_info_t *next;
	uint_t i;

	for (i = 0; i < core->core_nlwp; i++, lwp = list_next(lwp)) {
		if (lwp->lwp_id == id) {
			core->core_lwp = lwp;
			return (lwp);
		}
		if (lwp->lwp_id < id) {
			break;
		}
	}

	next = lwp;
	if ((lwp = calloc(1, sizeof (lwp_info_t))) == NULL)
		return (NULL);

	list_link(lwp, next);
	lwp->lwp_id = id;

	core->core_lwp = lwp;
	core->core_nlwp++;

	return (lwp);
}

/*
 * The core file itself contains a series of NOTE segments containing saved
 * structures from /proc at the time the process died.  For each note we
 * comprehend, we define a function to read it in from the core file,
 * convert it to our native data model if necessary, and store it inside
 * the ps_prochandle.  Each function is invoked by Pfgrab_core() with the
 * seek pointer on P->asfd positioned appropriately.  We populate a table
 * of pointers to these note functions below.
 */

static int
note_pstatus(struct ps_prochandle *P, size_t nbytes)
{
#ifdef _LP64
	core_info_t *core = P->data;

	if (core->core_dmodel == PR_MODEL_ILP32) {
		pstatus32_t ps32;

		if (nbytes < sizeof (pstatus32_t) ||
		    read(P->asfd, &ps32, sizeof (ps32)) != sizeof (ps32))
			goto err;

		pstatus_32_to_n(&ps32, &P->status);

	} else
#endif
	if (nbytes < sizeof (pstatus_t) ||
	    read(P->asfd, &P->status, sizeof (pstatus_t)) != sizeof (pstatus_t))
		goto err;

	P->orig_status = P->status;
	P->pid = P->status.pr_pid;

	return (0);

err:
	dprintf("Pgrab_core: failed to read NT_PSTATUS\n");
	return (-1);
}

static int
note_lwpstatus(struct ps_prochandle *P, size_t nbytes)
{
	lwp_info_t *lwp;
	lwpstatus_t lps;

#ifdef _LP64
	core_info_t *core = P->data;

	if (core->core_dmodel == PR_MODEL_ILP32) {
		lwpstatus32_t l32;

		if (nbytes < sizeof (lwpstatus32_t) ||
		    read(P->asfd, &l32, sizeof (l32)) != sizeof (l32))
			goto err;

		lwpstatus_32_to_n(&l32, &lps);
	} else
#endif
	if (nbytes < sizeof (lwpstatus_t) ||
	    read(P->asfd, &lps, sizeof (lps)) != sizeof (lps))
		goto err;

	if ((lwp = lwpid2info(P, lps.pr_lwpid)) == NULL) {
		dprintf("Pgrab_core: failed to add NT_LWPSTATUS\n");
		return (-1);
	}

	/*
	 * Erase a useless and confusing artifact of the kernel implementation:
	 * the lwps which did *not* create the core will show SIGKILL.  We can
	 * be assured this is bogus because SIGKILL can't produce core files.
	 */
	if (lps.pr_cursig == SIGKILL)
		lps.pr_cursig = 0;

	(void) memcpy(&lwp->lwp_status, &lps, sizeof (lps));
	return (0);

err:
	dprintf("Pgrab_core: failed to read NT_LWPSTATUS\n");
	return (-1);
}

#ifdef __x86

static void
lx_prpsinfo32_to_psinfo(lx_prpsinfo32_t *p32, psinfo_t *psinfo)
{
	psinfo->pr_flag = p32->pr_flag;
	psinfo->pr_pid = p32->pr_pid;
	psinfo->pr_ppid = p32->pr_ppid;
	psinfo->pr_uid = p32->pr_uid;
	psinfo->pr_gid = p32->pr_gid;
	psinfo->pr_sid = p32->pr_sid;
	psinfo->pr_pgid = p32->pr_pgrp;

	(void) memcpy(psinfo->pr_fname, p32->pr_fname,
	    sizeof (psinfo->pr_fname));
	(void) memcpy(psinfo->pr_psargs, p32->pr_psargs,
	    sizeof (psinfo->pr_psargs));
}

static void
lx_prpsinfo64_to_psinfo(lx_prpsinfo64_t *p64, psinfo_t *psinfo)
{
	psinfo->pr_flag = p64->pr_flag;
	psinfo->pr_pid = p64->pr_pid;
	psinfo->pr_ppid = p64->pr_ppid;
	psinfo->pr_uid = p64->pr_uid;
	psinfo->pr_gid = p64->pr_gid;
	psinfo->pr_sid = p64->pr_sid;
	psinfo->pr_pgid = p64->pr_pgrp;
	psinfo->pr_pgid = p64->pr_pgrp;

	(void) memcpy(psinfo->pr_fname, p64->pr_fname,
	    sizeof (psinfo->pr_fname));
	(void) memcpy(psinfo->pr_psargs, p64->pr_psargs,
	    sizeof (psinfo->pr_psargs));
}

static int
note_linux_psinfo(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	lx_prpsinfo32_t p32;
	lx_prpsinfo64_t p64;

	if (core->core_dmodel == PR_MODEL_ILP32) {
		if (nbytes < sizeof (p32) ||
		    read(P->asfd, &p32, sizeof (p32)) != sizeof (p32))
			goto err;

		lx_prpsinfo32_to_psinfo(&p32, &P->psinfo);
	} else {
		if (nbytes < sizeof (p64) ||
		    read(P->asfd, &p64, sizeof (p64)) != sizeof (p64))
			goto err;

		lx_prpsinfo64_to_psinfo(&p64, &P->psinfo);
	}


	P->status.pr_pid = P->psinfo.pr_pid;
	P->status.pr_ppid = P->psinfo.pr_ppid;
	P->status.pr_pgid = P->psinfo.pr_pgid;
	P->status.pr_sid = P->psinfo.pr_sid;

	P->psinfo.pr_nlwp = 0;
	P->status.pr_nlwp = 0;

	return (0);
err:
	dprintf("Pgrab_core: failed to read NT_PSINFO\n");
	return (-1);
}

static void
lx_prstatus64_to_lwp(lx_prstatus64_t *prs64, lwp_info_t *lwp)
{
	LTIME_TO_TIMESPEC(lwp->lwp_status.pr_utime, prs64->pr_utime);
	LTIME_TO_TIMESPEC(lwp->lwp_status.pr_stime, prs64->pr_stime);

	lwp->lwp_status.pr_reg[REG_R15] = prs64->pr_reg.lxr_r15;
	lwp->lwp_status.pr_reg[REG_R14] = prs64->pr_reg.lxr_r14;
	lwp->lwp_status.pr_reg[REG_R13] = prs64->pr_reg.lxr_r13;
	lwp->lwp_status.pr_reg[REG_R12] = prs64->pr_reg.lxr_r12;
	lwp->lwp_status.pr_reg[REG_R11] = prs64->pr_reg.lxr_r11;
	lwp->lwp_status.pr_reg[REG_R10] = prs64->pr_reg.lxr_r10;
	lwp->lwp_status.pr_reg[REG_R9] = prs64->pr_reg.lxr_r9;
	lwp->lwp_status.pr_reg[REG_R8] = prs64->pr_reg.lxr_r8;

	lwp->lwp_status.pr_reg[REG_RDI] = prs64->pr_reg.lxr_rdi;
	lwp->lwp_status.pr_reg[REG_RSI] = prs64->pr_reg.lxr_rsi;
	lwp->lwp_status.pr_reg[REG_RBP] = prs64->pr_reg.lxr_rbp;
	lwp->lwp_status.pr_reg[REG_RBX] = prs64->pr_reg.lxr_rbx;
	lwp->lwp_status.pr_reg[REG_RDX] = prs64->pr_reg.lxr_rdx;
	lwp->lwp_status.pr_reg[REG_RCX] = prs64->pr_reg.lxr_rcx;
	lwp->lwp_status.pr_reg[REG_RAX] = prs64->pr_reg.lxr_rax;

	lwp->lwp_status.pr_reg[REG_RIP] = prs64->pr_reg.lxr_rip;
	lwp->lwp_status.pr_reg[REG_CS] = prs64->pr_reg.lxr_cs;
	lwp->lwp_status.pr_reg[REG_RSP] = prs64->pr_reg.lxr_rsp;
	lwp->lwp_status.pr_reg[REG_FS] = prs64->pr_reg.lxr_fs;
	lwp->lwp_status.pr_reg[REG_SS] = prs64->pr_reg.lxr_ss;
	lwp->lwp_status.pr_reg[REG_GS] = prs64->pr_reg.lxr_gs;
	lwp->lwp_status.pr_reg[REG_ES] = prs64->pr_reg.lxr_es;
	lwp->lwp_status.pr_reg[REG_DS] = prs64->pr_reg.lxr_ds;

	lwp->lwp_status.pr_reg[REG_GSBASE] = prs64->pr_reg.lxr_gs_base;
	lwp->lwp_status.pr_reg[REG_FSBASE] = prs64->pr_reg.lxr_fs_base;
}

static void
lx_prstatus32_to_lwp(lx_prstatus32_t *prs32, lwp_info_t *lwp)
{
	LTIME_TO_TIMESPEC(lwp->lwp_status.pr_utime, prs32->pr_utime);
	LTIME_TO_TIMESPEC(lwp->lwp_status.pr_stime, prs32->pr_stime);

#ifdef __amd64
	lwp->lwp_status.pr_reg[REG_GS] = prs32->pr_reg.lxr_gs;
	lwp->lwp_status.pr_reg[REG_FS] = prs32->pr_reg.lxr_fs;
	lwp->lwp_status.pr_reg[REG_DS] = prs32->pr_reg.lxr_ds;
	lwp->lwp_status.pr_reg[REG_ES] = prs32->pr_reg.lxr_es;
	lwp->lwp_status.pr_reg[REG_RDI] = prs32->pr_reg.lxr_di;
	lwp->lwp_status.pr_reg[REG_RSI] = prs32->pr_reg.lxr_si;
	lwp->lwp_status.pr_reg[REG_RBP] = prs32->pr_reg.lxr_bp;
	lwp->lwp_status.pr_reg[REG_RBX] = prs32->pr_reg.lxr_bx;
	lwp->lwp_status.pr_reg[REG_RDX] = prs32->pr_reg.lxr_dx;
	lwp->lwp_status.pr_reg[REG_RCX] = prs32->pr_reg.lxr_cx;
	lwp->lwp_status.pr_reg[REG_RAX] = prs32->pr_reg.lxr_ax;
	lwp->lwp_status.pr_reg[REG_RIP] = prs32->pr_reg.lxr_ip;
	lwp->lwp_status.pr_reg[REG_CS] = prs32->pr_reg.lxr_cs;
	lwp->lwp_status.pr_reg[REG_RFL] = prs32->pr_reg.lxr_flags;
	lwp->lwp_status.pr_reg[REG_RSP] = prs32->pr_reg.lxr_sp;
	lwp->lwp_status.pr_reg[REG_SS] = prs32->pr_reg.lxr_ss;
#else /* __amd64 */
	lwp->lwp_status.pr_reg[EBX] = prs32->pr_reg.lxr_bx;
	lwp->lwp_status.pr_reg[ECX] = prs32->pr_reg.lxr_cx;
	lwp->lwp_status.pr_reg[EDX] = prs32->pr_reg.lxr_dx;
	lwp->lwp_status.pr_reg[ESI] = prs32->pr_reg.lxr_si;
	lwp->lwp_status.pr_reg[EDI] = prs32->pr_reg.lxr_di;
	lwp->lwp_status.pr_reg[EBP] = prs32->pr_reg.lxr_bp;
	lwp->lwp_status.pr_reg[EAX] = prs32->pr_reg.lxr_ax;
	lwp->lwp_status.pr_reg[EIP] = prs32->pr_reg.lxr_ip;
	lwp->lwp_status.pr_reg[UESP] = prs32->pr_reg.lxr_sp;

	lwp->lwp_status.pr_reg[DS] = prs32->pr_reg.lxr_ds;
	lwp->lwp_status.pr_reg[ES] = prs32->pr_reg.lxr_es;
	lwp->lwp_status.pr_reg[FS] = prs32->pr_reg.lxr_fs;
	lwp->lwp_status.pr_reg[GS] = prs32->pr_reg.lxr_gs;
	lwp->lwp_status.pr_reg[CS] = prs32->pr_reg.lxr_cs;
	lwp->lwp_status.pr_reg[SS] = prs32->pr_reg.lxr_ss;

	lwp->lwp_status.pr_reg[EFL] = prs32->pr_reg.lxr_flags;
#endif	/* !__amd64 */
}

static int
note_linux_prstatus(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;

	lx_prstatus64_t prs64;
	lx_prstatus32_t prs32;
	lwp_info_t *lwp;
	lwpid_t tid;

	dprintf("looking for model %d, %ld/%ld\n", core->core_dmodel,
	    (ulong_t)nbytes, (ulong_t)sizeof (prs32));
	if (core->core_dmodel == PR_MODEL_ILP32) {
		if (nbytes < sizeof (prs32) ||
		    read(P->asfd, &prs32, sizeof (prs32)) != nbytes)
			goto err;
		tid = prs32.pr_pid;
	} else {
		if (nbytes < sizeof (prs64) ||
		    read(P->asfd, &prs64, sizeof (prs64)) != nbytes)
			goto err;
		tid = prs64.pr_pid;
	}

	if ((lwp = lwpid2info(P, tid)) == NULL) {
		dprintf("Pgrab_core: failed to add lwpid2info "
		    "linux_prstatus\n");
		return (-1);
	}

	P->psinfo.pr_nlwp++;
	P->status.pr_nlwp++;

	lwp->lwp_status.pr_lwpid = tid;

	if (core->core_dmodel == PR_MODEL_ILP32)
		lx_prstatus32_to_lwp(&prs32, lwp);
	else
		lx_prstatus64_to_lwp(&prs64, lwp);

	return (0);
err:
	dprintf("Pgrab_core: failed to read NT_PRSTATUS\n");
	return (-1);
}

#endif /* __x86 */

static int
note_psinfo(struct ps_prochandle *P, size_t nbytes)
{
#ifdef _LP64
	core_info_t *core = P->data;

	if (core->core_dmodel == PR_MODEL_ILP32) {
		psinfo32_t ps32;

		if (nbytes < sizeof (psinfo32_t) ||
		    read(P->asfd, &ps32, sizeof (ps32)) != sizeof (ps32))
			goto err;

		psinfo_32_to_n(&ps32, &P->psinfo);
	} else
#endif
	if (nbytes < sizeof (psinfo_t) ||
	    read(P->asfd, &P->psinfo, sizeof (psinfo_t)) != sizeof (psinfo_t))
		goto err;

	dprintf("pr_fname = <%s>\n", P->psinfo.pr_fname);
	dprintf("pr_psargs = <%s>\n", P->psinfo.pr_psargs);
	dprintf("pr_wstat = 0x%x\n", P->psinfo.pr_wstat);

	return (0);

err:
	dprintf("Pgrab_core: failed to read NT_PSINFO\n");
	return (-1);
}

static int
note_lwpsinfo(struct ps_prochandle *P, size_t nbytes)
{
	lwp_info_t *lwp;
	lwpsinfo_t lps;

#ifdef _LP64
	core_info_t *core = P->data;

	if (core->core_dmodel == PR_MODEL_ILP32) {
		lwpsinfo32_t l32;

		if (nbytes < sizeof (lwpsinfo32_t) ||
		    read(P->asfd, &l32, sizeof (l32)) != sizeof (l32))
			goto err;

		lwpsinfo_32_to_n(&l32, &lps);
	} else
#endif
	if (nbytes < sizeof (lwpsinfo_t) ||
	    read(P->asfd, &lps, sizeof (lps)) != sizeof (lps))
		goto err;

	if ((lwp = lwpid2info(P, lps.pr_lwpid)) == NULL) {
		dprintf("Pgrab_core: failed to add NT_LWPSINFO\n");
		return (-1);
	}

	(void) memcpy(&lwp->lwp_psinfo, &lps, sizeof (lps));
	return (0);

err:
	dprintf("Pgrab_core: failed to read NT_LWPSINFO\n");
	return (-1);
}

static int
note_fdinfo(struct ps_prochandle *P, size_t nbytes)
{
	prfdinfo_t prfd;
	fd_info_t *fip;

	if ((nbytes < sizeof (prfd)) ||
	    (read(P->asfd, &prfd, sizeof (prfd)) != sizeof (prfd))) {
		dprintf("Pgrab_core: failed to read NT_FDINFO\n");
		return (-1);
	}

	if ((fip = Pfd2info(P, prfd.pr_fd)) == NULL) {
		dprintf("Pgrab_core: failed to add NT_FDINFO\n");
		return (-1);
	}
	(void) memcpy(&fip->fd_info, &prfd, sizeof (prfd));
	return (0);
}

static int
note_platform(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	char *plat;

	if (core->core_platform != NULL)
		return (0);	/* Already seen */

	if (nbytes != 0 && ((plat = malloc(nbytes + 1)) != NULL)) {
		if (read(P->asfd, plat, nbytes) != nbytes) {
			dprintf("Pgrab_core: failed to read NT_PLATFORM\n");
			free(plat);
			return (-1);
		}
		plat[nbytes - 1] = '\0';
		core->core_platform = plat;
	}

	return (0);
}

static int
note_secflags(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	prsecflags_t *psf;

	if (core->core_secflags != NULL)
		return (0);	/* Already seen */

	if (sizeof (*psf) != nbytes) {
		dprintf("Pgrab_core: NT_SECFLAGS changed size."
		    "  Need to handle a version change?\n");
		return (-1);
	}

	if (nbytes != 0 && ((psf = malloc(nbytes)) != NULL)) {
		if (read(P->asfd, psf, nbytes) != nbytes) {
			dprintf("Pgrab_core: failed to read NT_SECFLAGS\n");
			free(psf);
			return (-1);
		}

		core->core_secflags = psf;
	}

	return (0);
}

static int
note_utsname(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	size_t ubytes = sizeof (struct utsname);
	struct utsname *utsp;

	if (core->core_uts != NULL || nbytes < ubytes)
		return (0);	/* Already seen or bad size */

	if ((utsp = malloc(ubytes)) == NULL)
		return (-1);

	if (read(P->asfd, utsp, ubytes) != ubytes) {
		dprintf("Pgrab_core: failed to read NT_UTSNAME\n");
		free(utsp);
		return (-1);
	}

	if (_libproc_debug) {
		dprintf("uts.sysname = \"%s\"\n", utsp->sysname);
		dprintf("uts.nodename = \"%s\"\n", utsp->nodename);
		dprintf("uts.release = \"%s\"\n", utsp->release);
		dprintf("uts.version = \"%s\"\n", utsp->version);
		dprintf("uts.machine = \"%s\"\n", utsp->machine);
	}

	core->core_uts = utsp;
	return (0);
}

static int
note_content(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	core_content_t content;

	if (sizeof (core->core_content) != nbytes)
		return (-1);

	if (read(P->asfd, &content, sizeof (content)) != sizeof (content))
		return (-1);

	core->core_content = content;

	dprintf("core content = %llx\n", content);

	return (0);
}

static int
note_cred(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	prcred_t *pcrp;
	int ngroups;
	const size_t min_size = sizeof (prcred_t) - sizeof (gid_t);

	/*
	 * We allow for prcred_t notes that are actually smaller than a
	 * prcred_t since the last member isn't essential if there are
	 * no group memberships. This allows for more flexibility when it
	 * comes to slightly malformed -- but still valid -- notes.
	 */
	if (core->core_cred != NULL || nbytes < min_size)
		return (0);	/* Already seen or bad size */

	ngroups = (nbytes - min_size) / sizeof (gid_t);
	nbytes = sizeof (prcred_t) + (ngroups - 1) * sizeof (gid_t);

	if ((pcrp = malloc(nbytes)) == NULL)
		return (-1);

	if (read(P->asfd, pcrp, nbytes) != nbytes) {
		dprintf("Pgrab_core: failed to read NT_PRCRED\n");
		free(pcrp);
		return (-1);
	}

	if (pcrp->pr_ngroups > ngroups) {
		dprintf("pr_ngroups = %d; resetting to %d based on note size\n",
		    pcrp->pr_ngroups, ngroups);
		pcrp->pr_ngroups = ngroups;
	}

	core->core_cred = pcrp;
	return (0);
}

#ifdef __x86
static int
note_ldt(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	struct ssd *pldt;
	uint_t nldt;

	if (core->core_ldt != NULL || nbytes < sizeof (struct ssd))
		return (0);	/* Already seen or bad size */

	nldt = nbytes / sizeof (struct ssd);
	nbytes = nldt * sizeof (struct ssd);

	if ((pldt = malloc(nbytes)) == NULL)
		return (-1);

	if (read(P->asfd, pldt, nbytes) != nbytes) {
		dprintf("Pgrab_core: failed to read NT_LDT\n");
		free(pldt);
		return (-1);
	}

	core->core_ldt = pldt;
	core->core_nldt = nldt;
	return (0);
}
#endif	/* __i386 */

static int
note_priv(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	prpriv_t *pprvp;

	if (core->core_priv != NULL || nbytes < sizeof (prpriv_t))
		return (0);	/* Already seen or bad size */

	if ((pprvp = malloc(nbytes)) == NULL)
		return (-1);

	if (read(P->asfd, pprvp, nbytes) != nbytes) {
		dprintf("Pgrab_core: failed to read NT_PRPRIV\n");
		free(pprvp);
		return (-1);
	}

	core->core_priv = pprvp;
	core->core_priv_size = nbytes;
	return (0);
}

static int
note_priv_info(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	extern void *__priv_parse_info();
	priv_impl_info_t *ppii;

	if (core->core_privinfo != NULL ||
	    nbytes < sizeof (priv_impl_info_t))
		return (0);	/* Already seen or bad size */

	if ((ppii = malloc(nbytes)) == NULL)
		return (-1);

	if (read(P->asfd, ppii, nbytes) != nbytes ||
	    PRIV_IMPL_INFO_SIZE(ppii) != nbytes) {
		dprintf("Pgrab_core: failed to read NT_PRPRIVINFO\n");
		free(ppii);
		return (-1);
	}

	core->core_privinfo = __priv_parse_info(ppii);
	core->core_ppii = ppii;
	return (0);
}

static int
note_zonename(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	char *zonename;

	if (core->core_zonename != NULL)
		return (0);	/* Already seen */

	if (nbytes != 0) {
		if ((zonename = malloc(nbytes)) == NULL)
			return (-1);
		if (read(P->asfd, zonename, nbytes) != nbytes) {
			dprintf("Pgrab_core: failed to read NT_ZONENAME\n");
			free(zonename);
			return (-1);
		}
		zonename[nbytes - 1] = '\0';
		core->core_zonename = zonename;
	}

	return (0);
}

static int
note_auxv(struct ps_prochandle *P, size_t nbytes)
{
	size_t n, i;

#ifdef _LP64
	core_info_t *core = P->data;

	if (core->core_dmodel == PR_MODEL_ILP32) {
		auxv32_t *a32;

		n = nbytes / sizeof (auxv32_t);
		nbytes = n * sizeof (auxv32_t);
		a32 = alloca(nbytes);

		if (read(P->asfd, a32, nbytes) != nbytes) {
			dprintf("Pgrab_core: failed to read NT_AUXV\n");
			return (-1);
		}

		if ((P->auxv = malloc(sizeof (auxv_t) * (n + 1))) == NULL)
			return (-1);

		for (i = 0; i < n; i++)
			auxv_32_to_n(&a32[i], &P->auxv[i]);

	} else {
#endif
		n = nbytes / sizeof (auxv_t);
		nbytes = n * sizeof (auxv_t);

		if ((P->auxv = malloc(nbytes + sizeof (auxv_t))) == NULL)
			return (-1);

		if (read(P->asfd, P->auxv, nbytes) != nbytes) {
			free(P->auxv);
			P->auxv = NULL;
			return (-1);
		}
#ifdef _LP64
	}
#endif

	if (_libproc_debug) {
		for (i = 0; i < n; i++) {
			dprintf("P->auxv[%lu] = ( %d, 0x%lx )\n", (ulong_t)i,
			    P->auxv[i].a_type, P->auxv[i].a_un.a_val);
		}
	}

	/*
	 * Defensive coding for loops which depend upon the auxv array being
	 * terminated by an AT_NULL element; in each case, we've allocated
	 * P->auxv to have an additional element which we force to be AT_NULL.
	 */
	P->auxv[n].a_type = AT_NULL;
	P->auxv[n].a_un.a_val = 0L;
	P->nauxv = (int)n;

	return (0);
}

#ifdef __sparc
static int
note_xreg(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	lwp_info_t *lwp = core->core_lwp;
	size_t xbytes = sizeof (prxregset_t);
	prxregset_t *xregs;

	if (lwp == NULL || lwp->lwp_xregs != NULL || nbytes < xbytes)
		return (0);	/* No lwp yet, already seen, or bad size */

	if ((xregs = malloc(xbytes)) == NULL)
		return (-1);

	if (read(P->asfd, xregs, xbytes) != xbytes) {
		dprintf("Pgrab_core: failed to read NT_PRXREG\n");
		free(xregs);
		return (-1);
	}

	lwp->lwp_xregs = xregs;
	return (0);
}

static int
note_gwindows(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	lwp_info_t *lwp = core->core_lwp;

	if (lwp == NULL || lwp->lwp_gwins != NULL || nbytes == 0)
		return (0);	/* No lwp yet or already seen or no data */

	if ((lwp->lwp_gwins = malloc(sizeof (gwindows_t))) == NULL)
		return (-1);

	/*
	 * Since the amount of gwindows data varies with how many windows were
	 * actually saved, we just read up to the minimum of the note size
	 * and the size of the gwindows_t type.  It doesn't matter if the read
	 * fails since we have to zero out gwindows first anyway.
	 */
#ifdef _LP64
	if (core->core_dmodel == PR_MODEL_ILP32) {
		gwindows32_t g32;

		(void) memset(&g32, 0, sizeof (g32));
		(void) read(P->asfd, &g32, MIN(nbytes, sizeof (g32)));
		gwindows_32_to_n(&g32, lwp->lwp_gwins);

	} else {
#endif
		(void) memset(lwp->lwp_gwins, 0, sizeof (gwindows_t));
		(void) read(P->asfd, lwp->lwp_gwins,
		    MIN(nbytes, sizeof (gwindows_t)));
#ifdef _LP64
	}
#endif
	return (0);
}

#ifdef __sparcv9
static int
note_asrs(struct ps_prochandle *P, size_t nbytes)
{
	core_info_t *core = P->data;
	lwp_info_t *lwp = core->core_lwp;
	int64_t *asrs;

	if (lwp == NULL || lwp->lwp_asrs != NULL || nbytes < sizeof (asrset_t))
		return (0);	/* No lwp yet, already seen, or bad size */

	if ((asrs = malloc(sizeof (asrset_t))) == NULL)
		return (-1);

	if (read(P->asfd, asrs, sizeof (asrset_t)) != sizeof (asrset_t)) {
		dprintf("Pgrab_core: failed to read NT_ASRS\n");
		free(asrs);
		return (-1);
	}

	lwp->lwp_asrs = asrs;
	return (0);
}
#endif	/* __sparcv9 */
#endif	/* __sparc */

static int
note_spymaster(struct ps_prochandle *P, size_t nbytes)
{
#ifdef _LP64
	core_info_t *core = P->data;

	if (core->core_dmodel == PR_MODEL_ILP32) {
		psinfo32_t ps32;

		if (nbytes < sizeof (psinfo32_t) ||
		    read(P->asfd, &ps32, sizeof (ps32)) != sizeof (ps32))
			goto err;

		psinfo_32_to_n(&ps32, &P->spymaster);
	} else
#endif
	if (nbytes < sizeof (psinfo_t) || read(P->asfd,
	    &P->spymaster, sizeof (psinfo_t)) != sizeof (psinfo_t))
		goto err;

	dprintf("spymaster pr_fname = <%s>\n", P->psinfo.pr_fname);
	dprintf("spymaster pr_psargs = <%s>\n", P->psinfo.pr_psargs);
	dprintf("spymaster pr_wstat = 0x%x\n", P->psinfo.pr_wstat);

	return (0);

err:
	dprintf("Pgrab_core: failed to read NT_SPYMASTER\n");
	return (-1);
}

/*ARGSUSED*/
static int
note_notsup(struct ps_prochandle *P, size_t nbytes)
{
	dprintf("skipping unsupported note type of size %ld bytes\n",
	    (ulong_t)nbytes);
	return (0);
}

/*
 * Populate a table of function pointers indexed by Note type with our
 * functions to process each type of core file note:
 */
static int (*nhdlrs[])(struct ps_prochandle *, size_t) = {
	note_notsup,		/*  0	unassigned		*/
#ifdef __x86
	note_linux_prstatus,		/*  1	NT_PRSTATUS (old)	*/
#else
	note_notsup,		/*  1	NT_PRSTATUS (old)	*/
#endif
	note_notsup,		/*  2	NT_PRFPREG (old)	*/
#ifdef __x86
	note_linux_psinfo,		/*  3	NT_PRPSINFO (old)	*/
#else
	note_notsup,		/*  3	NT_PRPSINFO (old)	*/
#endif
#ifdef __sparc
	note_xreg,		/*  4	NT_PRXREG		*/
#else
	note_notsup,		/*  4	NT_PRXREG		*/
#endif
	note_platform,		/*  5	NT_PLATFORM		*/
	note_auxv,		/*  6	NT_AUXV			*/
#ifdef __sparc
	note_gwindows,		/*  7	NT_GWINDOWS		*/
#ifdef __sparcv9
	note_asrs,		/*  8	NT_ASRS			*/
#else
	note_notsup,		/*  8	NT_ASRS			*/
#endif
#else
	note_notsup,		/*  7	NT_GWINDOWS		*/
	note_notsup,		/*  8	NT_ASRS			*/
#endif
#ifdef __x86
	note_ldt,		/*  9	NT_LDT			*/
#else
	note_notsup,		/*  9	NT_LDT			*/
#endif
	note_pstatus,		/* 10	NT_PSTATUS		*/
	note_notsup,		/* 11	unassigned		*/
	note_notsup,		/* 12	unassigned		*/
	note_psinfo,		/* 13	NT_PSINFO		*/
	note_cred,		/* 14	NT_PRCRED		*/
	note_utsname,		/* 15	NT_UTSNAME		*/
	note_lwpstatus,		/* 16	NT_LWPSTATUS		*/
	note_lwpsinfo,		/* 17	NT_LWPSINFO		*/
	note_priv,		/* 18	NT_PRPRIV		*/
	note_priv_info,		/* 19	NT_PRPRIVINFO		*/
	note_content,		/* 20	NT_CONTENT		*/
	note_zonename,		/* 21	NT_ZONENAME		*/
	note_fdinfo,		/* 22	NT_FDINFO		*/
	note_spymaster,		/* 23	NT_SPYMASTER		*/
	note_secflags,		/* 24	NT_SECFLAGS		*/
};

static void
core_report_mapping(struct ps_prochandle *P, GElf_Phdr *php)
{
	prkillinfo_t killinfo;
	siginfo_t *si = &killinfo.prk_info;
	char signame[SIG2STR_MAX], sig[64], info[64];
	void *addr = (void *)(uintptr_t)php->p_vaddr;

	const char *errfmt = "core file data for mapping at %p not saved: %s\n";
	const char *incfmt = "core file incomplete due to %s%s\n";
	const char *msgfmt = "mappings at and above %p are missing\n";

	if (!(php->p_flags & PF_SUNW_KILLED)) {
		int err = 0;

		(void) pread64(P->asfd, &err,
		    sizeof (err), (off64_t)php->p_offset);

		Perror_printf(P, errfmt, addr, strerror(err));
		dprintf(errfmt, addr, strerror(err));
		return;
	}

	if (!(php->p_flags & PF_SUNW_SIGINFO))
		return;

	(void) memset(&killinfo, 0, sizeof (killinfo));

	(void) pread64(P->asfd, &killinfo,
	    sizeof (killinfo), (off64_t)php->p_offset);

	/*
	 * While there is (or at least should be) only one segment that has
	 * PF_SUNW_SIGINFO set, the signal information there is globally
	 * useful (even if only to those debugging libproc consumers); we hang
	 * the signal information gleaned here off of the ps_prochandle.
	 */
	P->map_missing = php->p_vaddr;
	P->killinfo = killinfo.prk_info;

	if (sig2str(si->si_signo, signame) == -1) {
		(void) snprintf(sig, sizeof (sig),
		    "<Unknown signal: 0x%x>, ", si->si_signo);
	} else {
		(void) snprintf(sig, sizeof (sig), "SIG%s, ", signame);
	}

	if (si->si_code == SI_USER || si->si_code == SI_QUEUE) {
		(void) snprintf(info, sizeof (info),
		    "pid=%d uid=%d zone=%d ctid=%d",
		    si->si_pid, si->si_uid, si->si_zoneid, si->si_ctid);
	} else {
		(void) snprintf(info, sizeof (info),
		    "code=%d", si->si_code);
	}

	Perror_printf(P, incfmt, sig, info);
	Perror_printf(P, msgfmt, addr);

	dprintf(incfmt, sig, info);
	dprintf(msgfmt, addr);
}

/*
 * Add information on the address space mapping described by the given
 * PT_LOAD program header.  We fill in more information on the mapping later.
 */
static int
core_add_mapping(struct ps_prochandle *P, GElf_Phdr *php)
{
	core_info_t *core = P->data;
	prmap_t pmap;

	dprintf("mapping base %llx filesz %llx memsz %llx offset %llx\n",
	    (u_longlong_t)php->p_vaddr, (u_longlong_t)php->p_filesz,
	    (u_longlong_t)php->p_memsz, (u_longlong_t)php->p_offset);

	pmap.pr_vaddr = (uintptr_t)php->p_vaddr;
	pmap.pr_size = php->p_memsz;

	/*
	 * If Pgcore() or elfcore() fail to write a mapping, they will set
	 * PF_SUNW_FAILURE in the Phdr and try to stash away the errno for us.
	 */
	if (php->p_flags & PF_SUNW_FAILURE) {
		core_report_mapping(P, php);
	} else if (php->p_filesz != 0 && php->p_offset >= core->core_size) {
		Perror_printf(P, "core file may be corrupt -- data for mapping "
		    "at %p is missing\n", (void *)(uintptr_t)php->p_vaddr);
		dprintf("core file may be corrupt -- data for mapping "
		    "at %p is missing\n", (void *)(uintptr_t)php->p_vaddr);
	}

	/*
	 * The mapping name and offset will hopefully be filled in
	 * by the librtld_db agent.  Unfortunately, if it isn't a
	 * shared library mapping, this information is gone forever.
	 */
	pmap.pr_mapname[0] = '\0';
	pmap.pr_offset = 0;

	pmap.pr_mflags = 0;
	if (php->p_flags & PF_R)
		pmap.pr_mflags |= MA_READ;
	if (php->p_flags & PF_W)
		pmap.pr_mflags |= MA_WRITE;
	if (php->p_flags & PF_X)
		pmap.pr_mflags |= MA_EXEC;

	if (php->p_filesz == 0)
		pmap.pr_mflags |= MA_RESERVED1;

	/*
	 * At the time of adding this mapping, we just zero the pagesize.
	 * Once we've processed more of the core file, we'll have the
	 * pagesize from the auxv's AT_PAGESZ element and we can fill this in.
	 */
	pmap.pr_pagesize = 0;

	/*
	 * Unfortunately whether or not the mapping was a System V
	 * shared memory segment is lost.  We use -1 to mark it as not shm.
	 */
	pmap.pr_shmid = -1;

	return (Padd_mapping(P, php->p_offset, NULL, &pmap));
}

/*
 * Given a virtual address, name the mapping at that address using the
 * specified name, and return the map_info_t pointer.
 */
static map_info_t *
core_name_mapping(struct ps_prochandle *P, uintptr_t addr, const char *name)
{
	map_info_t *mp = Paddr2mptr(P, addr);

	if (mp != NULL) {
		(void) strncpy(mp->map_pmap.pr_mapname, name, PRMAPSZ);
		mp->map_pmap.pr_mapname[PRMAPSZ - 1] = '\0';
	}

	return (mp);
}

/*
 * libproc uses libelf for all of its symbol table manipulation. This function
 * takes a symbol table and string table from a core file and places them
 * in a memory backed elf file.
 */
static void
fake_up_symtab(struct ps_prochandle *P, const elf_file_header_t *ehdr,
    GElf_Shdr *symtab, GElf_Shdr *strtab)
{
	size_t size;
	off64_t off, base;
	map_info_t *mp;
	file_info_t *fp;
	Elf_Scn *scn;
	Elf_Data *data;

	if (symtab->sh_addr == 0 ||
	    (mp = Paddr2mptr(P, symtab->sh_addr)) == NULL ||
	    (fp = mp->map_file) == NULL) {
		dprintf("fake_up_symtab: invalid section\n");
		return;
	}

	if (fp->file_symtab.sym_data_pri != NULL) {
		dprintf("Symbol table already loaded (sh_addr 0x%lx)\n",
		    (long)symtab->sh_addr);
		return;
	}

	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		struct {
			Elf32_Ehdr ehdr;
			Elf32_Shdr shdr[3];
			char data[1];
		} *b;

		base = sizeof (b->ehdr) + sizeof (b->shdr);
		size = base + symtab->sh_size + strtab->sh_size;

		if ((b = calloc(1, size)) == NULL)
			return;

		(void) memcpy(b->ehdr.e_ident, ehdr->e_ident,
		    sizeof (ehdr->e_ident));
		b->ehdr.e_type = ehdr->e_type;
		b->ehdr.e_machine = ehdr->e_machine;
		b->ehdr.e_version = ehdr->e_version;
		b->ehdr.e_flags = ehdr->e_flags;
		b->ehdr.e_ehsize = sizeof (b->ehdr);
		b->ehdr.e_shoff = sizeof (b->ehdr);
		b->ehdr.e_shentsize = sizeof (b->shdr[0]);
		b->ehdr.e_shnum = 3;
		off = 0;

		b->shdr[1].sh_size = symtab->sh_size;
		b->shdr[1].sh_type = SHT_SYMTAB;
		b->shdr[1].sh_offset = off + base;
		b->shdr[1].sh_entsize = sizeof (Elf32_Sym);
		b->shdr[1].sh_link = 2;
		b->shdr[1].sh_info =  symtab->sh_info;
		b->shdr[1].sh_addralign = symtab->sh_addralign;

		if (pread64(P->asfd, &b->data[off], b->shdr[1].sh_size,
		    symtab->sh_offset) != b->shdr[1].sh_size) {
			dprintf("fake_up_symtab: pread of symtab[1] failed\n");
			free(b);
			return;
		}

		off += b->shdr[1].sh_size;

		b->shdr[2].sh_flags = SHF_STRINGS;
		b->shdr[2].sh_size = strtab->sh_size;
		b->shdr[2].sh_type = SHT_STRTAB;
		b->shdr[2].sh_offset = off + base;
		b->shdr[2].sh_info =  strtab->sh_info;
		b->shdr[2].sh_addralign = 1;

		if (pread64(P->asfd, &b->data[off], b->shdr[2].sh_size,
		    strtab->sh_offset) != b->shdr[2].sh_size) {
			dprintf("fake_up_symtab: pread of symtab[2] failed\n");
			free(b);
			return;
		}

		off += b->shdr[2].sh_size;

		fp->file_symtab.sym_elf = elf_memory((char *)b, size);
		if (fp->file_symtab.sym_elf == NULL) {
			free(b);
			return;
		}

		fp->file_symtab.sym_elfmem = b;
#ifdef _LP64
	} else {
		struct {
			Elf64_Ehdr ehdr;
			Elf64_Shdr shdr[3];
			char data[1];
		} *b;

		base = sizeof (b->ehdr) + sizeof (b->shdr);
		size = base + symtab->sh_size + strtab->sh_size;

		if ((b = calloc(1, size)) == NULL)
			return;

		(void) memcpy(b->ehdr.e_ident, ehdr->e_ident,
		    sizeof (ehdr->e_ident));
		b->ehdr.e_type = ehdr->e_type;
		b->ehdr.e_machine = ehdr->e_machine;
		b->ehdr.e_version = ehdr->e_version;
		b->ehdr.e_flags = ehdr->e_flags;
		b->ehdr.e_ehsize = sizeof (b->ehdr);
		b->ehdr.e_shoff = sizeof (b->ehdr);
		b->ehdr.e_shentsize = sizeof (b->shdr[0]);
		b->ehdr.e_shnum = 3;
		off = 0;

		b->shdr[1].sh_size = symtab->sh_size;
		b->shdr[1].sh_type = SHT_SYMTAB;
		b->shdr[1].sh_offset = off + base;
		b->shdr[1].sh_entsize = sizeof (Elf64_Sym);
		b->shdr[1].sh_link = 2;
		b->shdr[1].sh_info =  symtab->sh_info;
		b->shdr[1].sh_addralign = symtab->sh_addralign;

		if (pread64(P->asfd, &b->data[off], b->shdr[1].sh_size,
		    symtab->sh_offset) != b->shdr[1].sh_size) {
			free(b);
			return;
		}

		off += b->shdr[1].sh_size;

		b->shdr[2].sh_flags = SHF_STRINGS;
		b->shdr[2].sh_size = strtab->sh_size;
		b->shdr[2].sh_type = SHT_STRTAB;
		b->shdr[2].sh_offset = off + base;
		b->shdr[2].sh_info =  strtab->sh_info;
		b->shdr[2].sh_addralign = 1;

		if (pread64(P->asfd, &b->data[off], b->shdr[2].sh_size,
		    strtab->sh_offset) != b->shdr[2].sh_size) {
			free(b);
			return;
		}

		off += b->shdr[2].sh_size;

		fp->file_symtab.sym_elf = elf_memory((char *)b, size);
		if (fp->file_symtab.sym_elf == NULL) {
			free(b);
			return;
		}

		fp->file_symtab.sym_elfmem = b;
#endif
	}

	if ((scn = elf_getscn(fp->file_symtab.sym_elf, 1)) == NULL ||
	    (fp->file_symtab.sym_data_pri = elf_getdata(scn, NULL)) == NULL ||
	    (scn = elf_getscn(fp->file_symtab.sym_elf, 2)) == NULL ||
	    (data = elf_getdata(scn, NULL)) == NULL) {
		dprintf("fake_up_symtab: failed to get section data at %p\n",
		    (void *)scn);
		goto err;
	}

	fp->file_symtab.sym_strs = data->d_buf;
	fp->file_symtab.sym_strsz = data->d_size;
	fp->file_symtab.sym_symn = symtab->sh_size / symtab->sh_entsize;
	fp->file_symtab.sym_hdr_pri = *symtab;
	fp->file_symtab.sym_strhdr = *strtab;

	optimize_symtab(&fp->file_symtab);

	return;
err:
	(void) elf_end(fp->file_symtab.sym_elf);
	free(fp->file_symtab.sym_elfmem);
	fp->file_symtab.sym_elf = NULL;
	fp->file_symtab.sym_elfmem = NULL;
}

static void
core_phdr_to_gelf(const Elf32_Phdr *src, GElf_Phdr *dst)
{
	dst->p_type = src->p_type;
	dst->p_flags = src->p_flags;
	dst->p_offset = (Elf64_Off)src->p_offset;
	dst->p_vaddr = (Elf64_Addr)src->p_vaddr;
	dst->p_paddr = (Elf64_Addr)src->p_paddr;
	dst->p_filesz = (Elf64_Xword)src->p_filesz;
	dst->p_memsz = (Elf64_Xword)src->p_memsz;
	dst->p_align = (Elf64_Xword)src->p_align;
}

static void
core_shdr_to_gelf(const Elf32_Shdr *src, GElf_Shdr *dst)
{
	dst->sh_name = src->sh_name;
	dst->sh_type = src->sh_type;
	dst->sh_flags = (Elf64_Xword)src->sh_flags;
	dst->sh_addr = (Elf64_Addr)src->sh_addr;
	dst->sh_offset = (Elf64_Off)src->sh_offset;
	dst->sh_size = (Elf64_Xword)src->sh_size;
	dst->sh_link = src->sh_link;
	dst->sh_info = src->sh_info;
	dst->sh_addralign = (Elf64_Xword)src->sh_addralign;
	dst->sh_entsize = (Elf64_Xword)src->sh_entsize;
}

/*
 * Perform elf_begin on efp->e_fd and verify the ELF file's type and class.
 */
static int
core_elf_fdopen(elf_file_t *efp, GElf_Half type, int *perr)
{
#ifdef _BIG_ENDIAN
	uchar_t order = ELFDATA2MSB;
#else
	uchar_t order = ELFDATA2LSB;
#endif
	Elf32_Ehdr e32;
	int is_noelf = -1;
	int isa_err = 0;

	/*
	 * Because 32-bit libelf cannot deal with large files, we need to read,
	 * check, and convert the file header manually in case type == ET_CORE.
	 */
	if (pread64(efp->e_fd, &e32, sizeof (e32), 0) != sizeof (e32)) {
		if (perr != NULL)
			*perr = G_FORMAT;
		goto err;
	}
	if ((is_noelf = memcmp(&e32.e_ident[EI_MAG0], ELFMAG, SELFMAG)) != 0 ||
	    e32.e_type != type || (isa_err = (e32.e_ident[EI_DATA] != order)) ||
	    e32.e_version != EV_CURRENT) {
		if (perr != NULL) {
			if (is_noelf == 0 && isa_err) {
				*perr = G_ISAINVAL;
			} else {
				*perr = G_FORMAT;
			}
		}
		goto err;
	}

	/*
	 * If the file is 64-bit and we are 32-bit, fail with G_LP64.  If the
	 * file is 64-bit and we are 64-bit, re-read the header as a Elf64_Ehdr,
	 * and convert it to a elf_file_header_t.  Otherwise, the file is
	 * 32-bit, so convert e32 to a elf_file_header_t.
	 */
	if (e32.e_ident[EI_CLASS] == ELFCLASS64) {
#ifdef _LP64
		Elf64_Ehdr e64;

		if (pread64(efp->e_fd, &e64, sizeof (e64), 0) != sizeof (e64)) {
			if (perr != NULL)
				*perr = G_FORMAT;
			goto err;
		}

		(void) memcpy(efp->e_hdr.e_ident, e64.e_ident, EI_NIDENT);
		efp->e_hdr.e_type = e64.e_type;
		efp->e_hdr.e_machine = e64.e_machine;
		efp->e_hdr.e_version = e64.e_version;
		efp->e_hdr.e_entry = e64.e_entry;
		efp->e_hdr.e_phoff = e64.e_phoff;
		efp->e_hdr.e_shoff = e64.e_shoff;
		efp->e_hdr.e_flags = e64.e_flags;
		efp->e_hdr.e_ehsize = e64.e_ehsize;
		efp->e_hdr.e_phentsize = e64.e_phentsize;
		efp->e_hdr.e_phnum = (Elf64_Word)e64.e_phnum;
		efp->e_hdr.e_shentsize = e64.e_shentsize;
		efp->e_hdr.e_shnum = (Elf64_Word)e64.e_shnum;
		efp->e_hdr.e_shstrndx = (Elf64_Word)e64.e_shstrndx;
#else	/* _LP64 */
		if (perr != NULL)
			*perr = G_LP64;
		goto err;
#endif	/* _LP64 */
	} else {
		(void) memcpy(efp->e_hdr.e_ident, e32.e_ident, EI_NIDENT);
		efp->e_hdr.e_type = e32.e_type;
		efp->e_hdr.e_machine = e32.e_machine;
		efp->e_hdr.e_version = e32.e_version;
		efp->e_hdr.e_entry = (Elf64_Addr)e32.e_entry;
		efp->e_hdr.e_phoff = (Elf64_Off)e32.e_phoff;
		efp->e_hdr.e_shoff = (Elf64_Off)e32.e_shoff;
		efp->e_hdr.e_flags = e32.e_flags;
		efp->e_hdr.e_ehsize = e32.e_ehsize;
		efp->e_hdr.e_phentsize = e32.e_phentsize;
		efp->e_hdr.e_phnum = (Elf64_Word)e32.e_phnum;
		efp->e_hdr.e_shentsize = e32.e_shentsize;
		efp->e_hdr.e_shnum = (Elf64_Word)e32.e_shnum;
		efp->e_hdr.e_shstrndx = (Elf64_Word)e32.e_shstrndx;
	}

	/*
	 * If the number of section headers or program headers or the section
	 * header string table index would overflow their respective fields
	 * in the ELF header, they're stored in the section header at index
	 * zero. To simplify use elsewhere, we look for those sentinel values
	 * here.
	 */
	if ((efp->e_hdr.e_shnum == 0 && efp->e_hdr.e_shoff != 0) ||
	    efp->e_hdr.e_shstrndx == SHN_XINDEX ||
	    efp->e_hdr.e_phnum == PN_XNUM) {
		GElf_Shdr shdr;

		dprintf("extended ELF header\n");

		if (efp->e_hdr.e_shoff == 0) {
			if (perr != NULL)
				*perr = G_FORMAT;
			goto err;
		}

		if (efp->e_hdr.e_ident[EI_CLASS] == ELFCLASS32) {
			Elf32_Shdr shdr32;

			if (pread64(efp->e_fd, &shdr32, sizeof (shdr32),
			    efp->e_hdr.e_shoff) != sizeof (shdr32)) {
				if (perr != NULL)
					*perr = G_FORMAT;
				goto err;
			}

			core_shdr_to_gelf(&shdr32, &shdr);
		} else {
			if (pread64(efp->e_fd, &shdr, sizeof (shdr),
			    efp->e_hdr.e_shoff) != sizeof (shdr)) {
				if (perr != NULL)
					*perr = G_FORMAT;
				goto err;
			}
		}

		if (efp->e_hdr.e_shnum == 0) {
			efp->e_hdr.e_shnum = shdr.sh_size;
			dprintf("section header count %lu\n",
			    (ulong_t)shdr.sh_size);
		}

		if (efp->e_hdr.e_shstrndx == SHN_XINDEX) {
			efp->e_hdr.e_shstrndx = shdr.sh_link;
			dprintf("section string index %u\n", shdr.sh_link);
		}

		if (efp->e_hdr.e_phnum == PN_XNUM && shdr.sh_info != 0) {
			efp->e_hdr.e_phnum = shdr.sh_info;
			dprintf("program header count %u\n", shdr.sh_info);
		}

	} else if (efp->e_hdr.e_phoff != 0) {
		GElf_Phdr phdr;
		uint64_t phnum;

		/*
		 * It's possible this core file came from a system that
		 * accidentally truncated the e_phnum field without correctly
		 * using the extended format in the section header at index
		 * zero. We try to detect and correct that specific type of
		 * corruption by using the knowledge that the core dump
		 * routines usually place the data referenced by the first
		 * program header immediately after the last header element.
		 */
		if (efp->e_hdr.e_ident[EI_CLASS] == ELFCLASS32) {
			Elf32_Phdr phdr32;

			if (pread64(efp->e_fd, &phdr32, sizeof (phdr32),
			    efp->e_hdr.e_phoff) != sizeof (phdr32)) {
				if (perr != NULL)
					*perr = G_FORMAT;
				goto err;
			}

			core_phdr_to_gelf(&phdr32, &phdr);
		} else {
			if (pread64(efp->e_fd, &phdr, sizeof (phdr),
			    efp->e_hdr.e_phoff) != sizeof (phdr)) {
				if (perr != NULL)
					*perr = G_FORMAT;
				goto err;
			}
		}

		phnum = phdr.p_offset - efp->e_hdr.e_ehsize -
		    (uint64_t)efp->e_hdr.e_shnum * efp->e_hdr.e_shentsize;
		phnum /= efp->e_hdr.e_phentsize;

		if (phdr.p_offset != 0 && phnum != efp->e_hdr.e_phnum) {
			dprintf("suspicious program header count %u %u\n",
			    (uint_t)phnum, efp->e_hdr.e_phnum);

			/*
			 * If the new program header count we computed doesn't
			 * jive with count in the ELF header, we'll use the
			 * data that's there and hope for the best.
			 *
			 * If it does, it's also possible that the section
			 * header offset is incorrect; we'll check that and
			 * possibly try to fix it.
			 */
			if (phnum <= INT_MAX &&
			    (uint16_t)phnum == efp->e_hdr.e_phnum) {

				if (efp->e_hdr.e_shoff == efp->e_hdr.e_phoff +
				    efp->e_hdr.e_phentsize *
				    (uint_t)efp->e_hdr.e_phnum) {
					efp->e_hdr.e_shoff =
					    efp->e_hdr.e_phoff +
					    efp->e_hdr.e_phentsize * phnum;
				}

				efp->e_hdr.e_phnum = (Elf64_Word)phnum;
				dprintf("using new program header count\n");
			} else {
				dprintf("inconsistent program header count\n");
			}
		}
	}

	/*
	 * The libelf implementation was never ported to be large-file aware.
	 * This is typically not a problem for your average executable or
	 * shared library, but a large 32-bit core file can exceed 2GB in size.
	 * So if type is ET_CORE, we don't bother doing elf_begin; the code
	 * in Pfgrab_core() below will do its own i/o and struct conversion.
	 */

	if (type == ET_CORE) {
		efp->e_elf = NULL;
		return (0);
	}

	if ((efp->e_elf = elf_begin(efp->e_fd, ELF_C_READ, NULL)) == NULL) {
		if (perr != NULL)
			*perr = G_ELF;
		goto err;
	}

	return (0);

err:
	efp->e_elf = NULL;
	return (-1);
}

/*
 * Open the specified file and then do a core_elf_fdopen on it.
 */
static int
core_elf_open(elf_file_t *efp, const char *path, GElf_Half type, int *perr)
{
	(void) memset(efp, 0, sizeof (elf_file_t));

	if ((efp->e_fd = open64(path, O_RDONLY)) >= 0) {
		if (core_elf_fdopen(efp, type, perr) == 0)
			return (0);

		(void) close(efp->e_fd);
		efp->e_fd = -1;
	}

	return (-1);
}

/*
 * Close the ELF handle and file descriptor.
 */
static void
core_elf_close(elf_file_t *efp)
{
	if (efp->e_elf != NULL) {
		(void) elf_end(efp->e_elf);
		efp->e_elf = NULL;
	}

	if (efp->e_fd != -1) {
		(void) close(efp->e_fd);
		efp->e_fd = -1;
	}
}

/*
 * Given an ELF file for a statically linked executable, locate the likely
 * primary text section and fill in rl_base with its virtual address.
 */
static map_info_t *
core_find_text(struct ps_prochandle *P, Elf *elf, rd_loadobj_t *rlp)
{
	GElf_Phdr phdr;
	uint_t i;
	size_t nphdrs;

	if (elf_getphdrnum(elf, &nphdrs) == -1)
		return (NULL);

	for (i = 0; i < nphdrs; i++) {
		if (gelf_getphdr(elf, i, &phdr) != NULL &&
		    phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
			rlp->rl_base = phdr.p_vaddr;
			return (Paddr2mptr(P, rlp->rl_base));
		}
	}

	return (NULL);
}

/*
 * Given an ELF file and the librtld_db structure corresponding to its primary
 * text mapping, deduce where its data segment was loaded and fill in
 * rl_data_base and prmap_t.pr_offset accordingly.
 */
static map_info_t *
core_find_data(struct ps_prochandle *P, Elf *elf, rd_loadobj_t *rlp)
{
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;
	map_info_t *mp;
	uint_t i, pagemask;
	size_t nphdrs;

	rlp->rl_data_base = NULL;

	/*
	 * Find the first loadable, writeable Phdr and compute rl_data_base
	 * as the virtual address at which is was loaded.
	 */
	if (gelf_getehdr(elf, &ehdr) == NULL ||
	    elf_getphdrnum(elf, &nphdrs) == -1)
		return (NULL);

	for (i = 0; i < nphdrs; i++) {
		if (gelf_getphdr(elf, i, &phdr) != NULL &&
		    phdr.p_type == PT_LOAD && (phdr.p_flags & PF_W)) {
			rlp->rl_data_base = phdr.p_vaddr;
			if (ehdr.e_type == ET_DYN)
				rlp->rl_data_base += rlp->rl_base;
			break;
		}
	}

	/*
	 * If we didn't find an appropriate phdr or if the address we
	 * computed has no mapping, return NULL.
	 */
	if (rlp->rl_data_base == NULL ||
	    (mp = Paddr2mptr(P, rlp->rl_data_base)) == NULL)
		return (NULL);

	/*
	 * It wouldn't be procfs-related code if we didn't make use of
	 * unclean knowledge of segvn, even in userland ... the prmap_t's
	 * pr_offset field will be the segvn offset from mmap(2)ing the
	 * data section, which will be the file offset & PAGEMASK.
	 */
	pagemask = ~(mp->map_pmap.pr_pagesize - 1);
	mp->map_pmap.pr_offset = phdr.p_offset & pagemask;

	return (mp);
}

/*
 * Librtld_db agent callback for iterating over load object mappings.
 * For each load object, we allocate a new file_info_t, perform naming,
 * and attempt to construct a symbol table for the load object.
 */
static int
core_iter_mapping(const rd_loadobj_t *rlp, struct ps_prochandle *P)
{
	core_info_t *core = P->data;
	char lname[PATH_MAX], buf[PATH_MAX];
	file_info_t *fp;
	map_info_t *mp;

	if (Pread_string(P, lname, PATH_MAX, (off_t)rlp->rl_nameaddr) <= 0) {
		dprintf("failed to read name %p\n", (void *)rlp->rl_nameaddr);
		return (1); /* Keep going; forget this if we can't get a name */
	}

	dprintf("rd_loadobj name = \"%s\" rl_base = %p\n",
	    lname, (void *)rlp->rl_base);

	if ((mp = Paddr2mptr(P, rlp->rl_base)) == NULL) {
		dprintf("no mapping for %p\n", (void *)rlp->rl_base);
		return (1); /* No mapping; advance to next mapping */
	}

	/*
	 * Create a new file_info_t for this mapping, and therefore for
	 * this load object.
	 *
	 * If there's an ELF header at the beginning of this mapping,
	 * file_info_new() will try to use its section headers to
	 * identify any other mappings that belong to this load object.
	 */
	if ((fp = mp->map_file) == NULL &&
	    (fp = file_info_new(P, mp)) == NULL) {
		core->core_errno = errno;
		dprintf("failed to malloc mapping data\n");
		return (0); /* Abort */
	}
	fp->file_map = mp;

	/* Create a local copy of the load object representation */
	if ((fp->file_lo = calloc(1, sizeof (rd_loadobj_t))) == NULL) {
		core->core_errno = errno;
		dprintf("failed to malloc mapping data\n");
		return (0); /* Abort */
	}
	*fp->file_lo = *rlp;

	if (lname[0] != '\0') {
		/*
		 * Naming dance part 1: if we got a name from librtld_db, then
		 * copy this name to the prmap_t if it is unnamed.  If the
		 * file_info_t is unnamed, name it after the lname.
		 */
		if (mp->map_pmap.pr_mapname[0] == '\0') {
			(void) strncpy(mp->map_pmap.pr_mapname, lname, PRMAPSZ);
			mp->map_pmap.pr_mapname[PRMAPSZ - 1] = '\0';
		}

		if (fp->file_lname == NULL)
			fp->file_lname = strdup(lname);

	} else if (fp->file_lname == NULL &&
	    mp->map_pmap.pr_mapname[0] != '\0') {
		/*
		 * Naming dance part 2: if the mapping is named and the
		 * file_info_t is not, name the file after the mapping.
		 */
		fp->file_lname = strdup(mp->map_pmap.pr_mapname);
	}

	if ((fp->file_rname == NULL) &&
	    (Pfindmap(P, mp, buf, sizeof (buf)) != NULL))
		fp->file_rname = strdup(buf);

	if (fp->file_lname != NULL)
		fp->file_lbase = basename(fp->file_lname);
	if (fp->file_rname != NULL)
		fp->file_rbase = basename(fp->file_rname);

	/* Associate the file and the mapping. */
	(void) strncpy(fp->file_pname, mp->map_pmap.pr_mapname, PRMAPSZ);
	fp->file_pname[PRMAPSZ - 1] = '\0';

	/*
	 * If no section headers were available then we'll have to
	 * identify this load object's other mappings with what we've
	 * got: the start and end of the object's corresponding
	 * address space.
	 */
	if (fp->file_saddrs == NULL) {
		for (mp = fp->file_map + 1; mp < P->mappings + P->map_count &&
		    mp->map_pmap.pr_vaddr < rlp->rl_bend; mp++) {

			if (mp->map_file == NULL) {
				dprintf("core_iter_mapping %s: associating "
				    "segment at %p\n",
				    fp->file_pname,
				    (void *)mp->map_pmap.pr_vaddr);
				mp->map_file = fp;
				fp->file_ref++;
			} else {
				dprintf("core_iter_mapping %s: segment at "
				    "%p already associated with %s\n",
				    fp->file_pname,
				    (void *)mp->map_pmap.pr_vaddr,
				    (mp == fp->file_map ? "this file" :
				    mp->map_file->file_pname));
			}
		}
	}

	/* Ensure that all this file's mappings are named. */
	for (mp = fp->file_map; mp < P->mappings + P->map_count &&
	    mp->map_file == fp; mp++) {
		if (mp->map_pmap.pr_mapname[0] == '\0' &&
		    !(mp->map_pmap.pr_mflags & MA_BREAK)) {
			(void) strncpy(mp->map_pmap.pr_mapname, fp->file_pname,
			    PRMAPSZ);
			mp->map_pmap.pr_mapname[PRMAPSZ - 1] = '\0';
		}
	}

	/* Attempt to build a symbol table for this file. */
	Pbuild_file_symtab(P, fp);
	if (fp->file_elf == NULL)
		dprintf("core_iter_mapping: no symtab for %s\n",
		    fp->file_pname);

	/* Locate the start of a data segment associated with this file. */
	if ((mp = core_find_data(P, fp->file_elf, fp->file_lo)) != NULL) {
		dprintf("found data for %s at %p (pr_offset 0x%llx)\n",
		    fp->file_pname, (void *)fp->file_lo->rl_data_base,
		    mp->map_pmap.pr_offset);
	} else {
		dprintf("core_iter_mapping: no data found for %s\n",
		    fp->file_pname);
	}

	return (1); /* Advance to next mapping */
}

/*
 * Callback function for Pfindexec().  In order to confirm a given pathname,
 * we verify that we can open it as an ELF file of type ET_EXEC or ET_DYN.
 */
static int
core_exec_open(const char *path, void *efp)
{
	if (core_elf_open(efp, path, ET_EXEC, NULL) == 0)
		return (1);
	if (core_elf_open(efp, path, ET_DYN, NULL) == 0)
		return (1);
	return (0);
}

/*
 * Attempt to load any section headers found in the core file.  If present,
 * this will refer to non-loadable data added to the core file by the kernel
 * based on coreadm(1M) settings, including CTF data and the symbol table.
 */
static void
core_load_shdrs(struct ps_prochandle *P, elf_file_t *efp)
{
	GElf_Shdr *shp, *shdrs = NULL;
	char *shstrtab = NULL;
	ulong_t shstrtabsz;
	const char *name;
	map_info_t *mp;

	size_t nbytes;
	void *buf;
	int i;

	if (efp->e_hdr.e_shstrndx >= efp->e_hdr.e_shnum) {
		dprintf("corrupt shstrndx (%u) exceeds shnum (%u)\n",
		    efp->e_hdr.e_shstrndx, efp->e_hdr.e_shnum);
		return;
	}

	/*
	 * Read the section header table from the core file and then iterate
	 * over the section headers, converting each to a GElf_Shdr.
	 */
	if ((shdrs = malloc(efp->e_hdr.e_shnum * sizeof (GElf_Shdr))) == NULL) {
		dprintf("failed to malloc %u section headers: %s\n",
		    (uint_t)efp->e_hdr.e_shnum, strerror(errno));
		return;
	}

	nbytes = efp->e_hdr.e_shnum * efp->e_hdr.e_shentsize;
	if ((buf = malloc(nbytes)) == NULL) {
		dprintf("failed to malloc %d bytes: %s\n", (int)nbytes,
		    strerror(errno));
		free(shdrs);
		goto out;
	}

	if (pread64(efp->e_fd, buf, nbytes, efp->e_hdr.e_shoff) != nbytes) {
		dprintf("failed to read section headers at off %lld: %s\n",
		    (longlong_t)efp->e_hdr.e_shoff, strerror(errno));
		free(buf);
		goto out;
	}

	for (i = 0; i < efp->e_hdr.e_shnum; i++) {
		void *p = (uchar_t *)buf + efp->e_hdr.e_shentsize * i;

		if (efp->e_hdr.e_ident[EI_CLASS] == ELFCLASS32)
			core_shdr_to_gelf(p, &shdrs[i]);
		else
			(void) memcpy(&shdrs[i], p, sizeof (GElf_Shdr));
	}

	free(buf);
	buf = NULL;

	/*
	 * Read the .shstrtab section from the core file, terminating it with
	 * an extra \0 so that a corrupt section will not cause us to die.
	 */
	shp = &shdrs[efp->e_hdr.e_shstrndx];
	shstrtabsz = shp->sh_size;

	if ((shstrtab = malloc(shstrtabsz + 1)) == NULL) {
		dprintf("failed to allocate %lu bytes for shstrtab\n",
		    (ulong_t)shstrtabsz);
		goto out;
	}

	if (pread64(efp->e_fd, shstrtab, shstrtabsz,
	    shp->sh_offset) != shstrtabsz) {
		dprintf("failed to read %lu bytes of shstrs at off %lld: %s\n",
		    shstrtabsz, (longlong_t)shp->sh_offset, strerror(errno));
		goto out;
	}

	shstrtab[shstrtabsz] = '\0';

	/*
	 * Now iterate over each section in the section header table, locating
	 * sections of interest and initializing more of the ps_prochandle.
	 */
	for (i = 0; i < efp->e_hdr.e_shnum; i++) {
		shp = &shdrs[i];
		name = shstrtab + shp->sh_name;

		if (shp->sh_name >= shstrtabsz) {
			dprintf("skipping section [%d]: corrupt sh_name\n", i);
			continue;
		}

		if (shp->sh_link >= efp->e_hdr.e_shnum) {
			dprintf("skipping section [%d]: corrupt sh_link\n", i);
			continue;
		}

		dprintf("found section header %s (sh_addr 0x%llx)\n",
		    name, (u_longlong_t)shp->sh_addr);

		if (strcmp(name, ".SUNW_ctf") == 0) {
			if ((mp = Paddr2mptr(P, shp->sh_addr)) == NULL) {
				dprintf("no map at addr 0x%llx for %s [%d]\n",
				    (u_longlong_t)shp->sh_addr, name, i);
				continue;
			}

			if (mp->map_file == NULL ||
			    mp->map_file->file_ctf_buf != NULL) {
				dprintf("no mapping file or duplicate buffer "
				    "for %s [%d]\n", name, i);
				continue;
			}

			if ((buf = malloc(shp->sh_size)) == NULL ||
			    pread64(efp->e_fd, buf, shp->sh_size,
			    shp->sh_offset) != shp->sh_size) {
				dprintf("skipping section %s [%d]: %s\n",
				    name, i, strerror(errno));
				free(buf);
				continue;
			}

			mp->map_file->file_ctf_size = shp->sh_size;
			mp->map_file->file_ctf_buf = buf;

			if (shdrs[shp->sh_link].sh_type == SHT_DYNSYM)
				mp->map_file->file_ctf_dyn = 1;

		} else if (strcmp(name, ".symtab") == 0) {
			fake_up_symtab(P, &efp->e_hdr,
			    shp, &shdrs[shp->sh_link]);
		}
	}
out:
	free(shstrtab);
	free(shdrs);
}

/*
 * Main engine for core file initialization: given an fd for the core file
 * and an optional pathname, construct the ps_prochandle.  The aout_path can
 * either be a suggested executable pathname, or a suggested directory to
 * use as a possible current working directory.
 */
struct ps_prochandle *
Pfgrab_core(int core_fd, const char *aout_path, int *perr)
{
	struct ps_prochandle *P;
	core_info_t *core_info;
	map_info_t *stk_mp, *brk_mp;
	const char *execname;
	char *interp;
	int i, notes, pagesize;
	uintptr_t addr, base_addr;
	struct stat64 stbuf;
	void *phbuf, *php;
	size_t nbytes;
#ifdef __x86
	boolean_t from_linux = B_FALSE;
#endif

	elf_file_t aout;
	elf_file_t core;

	Elf_Scn *scn, *intp_scn = NULL;
	Elf_Data *dp;

	GElf_Phdr phdr, note_phdr;
	GElf_Shdr shdr;
	GElf_Xword nleft;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		dprintf("libproc ELF version is more recent than libelf\n");
		*perr = G_ELF;
		return (NULL);
	}

	aout.e_elf = NULL;
	aout.e_fd = -1;

	core.e_elf = NULL;
	core.e_fd = core_fd;

	/*
	 * Allocate and initialize a ps_prochandle structure for the core.
	 * There are several key pieces of initialization here:
	 *
	 * 1. The PS_DEAD state flag marks this prochandle as a core file.
	 *    PS_DEAD also thus prevents all operations which require state
	 *    to be PS_STOP from operating on this handle.
	 *
	 * 2. We keep the core file fd in P->asfd since the core file contains
	 *    the remnants of the process address space.
	 *
	 * 3. We set the P->info_valid bit because all information about the
	 *    core is determined by the end of this function; there is no need
	 *    for proc_update_maps() to reload mappings at any later point.
	 *
	 * 4. The read/write ops vector uses our core_rw() function defined
	 *    above to handle i/o requests.
	 */
	if ((P = malloc(sizeof (struct ps_prochandle))) == NULL) {
		*perr = G_STRANGE;
		return (NULL);
	}

	(void) memset(P, 0, sizeof (struct ps_prochandle));
	(void) mutex_init(&P->proc_lock, USYNC_THREAD, NULL);
	P->state = PS_DEAD;
	P->pid = (pid_t)-1;
	P->asfd = core.e_fd;
	P->ctlfd = -1;
	P->statfd = -1;
	P->agentctlfd = -1;
	P->agentstatfd = -1;
	P->zoneroot = NULL;
	P->info_valid = 1;
	Pinit_ops(&P->ops, &P_core_ops);

	Pinitsym(P);

	/*
	 * Fstat and open the core file and make sure it is a valid ELF core.
	 */
	if (fstat64(P->asfd, &stbuf) == -1) {
		*perr = G_STRANGE;
		goto err;
	}

	if (core_elf_fdopen(&core, ET_CORE, perr) == -1)
		goto err;

	/*
	 * Allocate and initialize a core_info_t to hang off the ps_prochandle
	 * structure.  We keep all core-specific information in this structure.
	 */
	if ((core_info = calloc(1, sizeof (core_info_t))) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}

	P->data = core_info;
	list_link(&core_info->core_lwp_head, NULL);
	core_info->core_size = stbuf.st_size;
	/*
	 * In the days before adjustable core file content, this was the
	 * default core file content. For new core files, this value will
	 * be overwritten by the NT_CONTENT note section.
	 */
	core_info->core_content = CC_CONTENT_STACK | CC_CONTENT_HEAP |
	    CC_CONTENT_DATA | CC_CONTENT_RODATA | CC_CONTENT_ANON |
	    CC_CONTENT_SHANON;

	switch (core.e_hdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		core_info->core_dmodel = PR_MODEL_ILP32;
		break;
	case ELFCLASS64:
		core_info->core_dmodel = PR_MODEL_LP64;
		break;
	default:
		*perr = G_FORMAT;
		goto err;
	}
	core_info->core_osabi = core.e_hdr.e_ident[EI_OSABI];

	/*
	 * Because the core file may be a large file, we can't use libelf to
	 * read the Phdrs.  We use e_phnum and e_phentsize to simplify things.
	 */
	nbytes = core.e_hdr.e_phnum * core.e_hdr.e_phentsize;

	if ((phbuf = malloc(nbytes)) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}

	if (pread64(core_fd, phbuf, nbytes, core.e_hdr.e_phoff) != nbytes) {
		*perr = G_STRANGE;
		free(phbuf);
		goto err;
	}

	/*
	 * Iterate through the program headers in the core file.
	 * We're interested in two types of Phdrs: PT_NOTE (which
	 * contains a set of saved /proc structures), and PT_LOAD (which
	 * represents a memory mapping from the process's address space).
	 * In the case of PT_NOTE, we're interested in the last PT_NOTE
	 * in the core file; currently the first PT_NOTE (if present)
	 * contains /proc structs in the pre-2.6 unstructured /proc format.
	 */
	for (php = phbuf, notes = 0, i = 0; i < core.e_hdr.e_phnum; i++) {
		if (core.e_hdr.e_ident[EI_CLASS] == ELFCLASS64)
			(void) memcpy(&phdr, php, sizeof (GElf_Phdr));
		else
			core_phdr_to_gelf(php, &phdr);

		switch (phdr.p_type) {
		case PT_NOTE:
			note_phdr = phdr;
			notes++;
			break;

		case PT_LOAD:
			if (core_add_mapping(P, &phdr) == -1) {
				*perr = G_STRANGE;
				free(phbuf);
				goto err;
			}
			break;
		default:
			dprintf("Pgrab_core: unknown phdr %d\n", phdr.p_type);
			break;
		}

		php = (char *)php + core.e_hdr.e_phentsize;
	}

	free(phbuf);

	Psort_mappings(P);

	/*
	 * If we couldn't find anything of type PT_NOTE, or only one PT_NOTE
	 * was present, abort.  The core file is either corrupt or too old.
	 */
	if (notes == 0 || (notes == 1 && core_info->core_osabi ==
	    ELFOSABI_SOLARIS)) {
		*perr = G_NOTE;
		goto err;
	}

	/*
	 * Advance the seek pointer to the start of the PT_NOTE data
	 */
	if (lseek64(P->asfd, note_phdr.p_offset, SEEK_SET) == (off64_t)-1) {
		dprintf("Pgrab_core: failed to lseek to PT_NOTE data\n");
		*perr = G_STRANGE;
		goto err;
	}

	/*
	 * Now process the PT_NOTE structures.  Each one is preceded by
	 * an Elf{32/64}_Nhdr structure describing its type and size.
	 *
	 *  +--------+
	 *  | header |
	 *  +--------+
	 *  | name   |
	 *  | ...    |
	 *  +--------+
	 *  | desc   |
	 *  | ...    |
	 *  +--------+
	 */
	for (nleft = note_phdr.p_filesz; nleft > 0; ) {
		Elf64_Nhdr nhdr;
		off64_t off, namesz, descsz;

		/*
		 * Although <sys/elf.h> defines both Elf32_Nhdr and Elf64_Nhdr
		 * as different types, they are both of the same content and
		 * size, so we don't need to worry about 32/64 conversion here.
		 */
		if (read(P->asfd, &nhdr, sizeof (nhdr)) != sizeof (nhdr)) {
			dprintf("Pgrab_core: failed to read ELF note header\n");
			*perr = G_NOTE;
			goto err;
		}

		/*
		 * According to the System V ABI, the amount of padding
		 * following the name field should align the description
		 * field on a 4 byte boundary for 32-bit binaries or on an 8
		 * byte boundary for 64-bit binaries. However, this change
		 * was not made correctly during the 64-bit port so all
		 * descriptions can assume only 4-byte alignment. We ignore
		 * the name field and the padding to 4-byte alignment.
		 */
		namesz = P2ROUNDUP((off64_t)nhdr.n_namesz, (off64_t)4);

		if (lseek64(P->asfd, namesz, SEEK_CUR) == (off64_t)-1) {
			dprintf("failed to seek past name and padding\n");
			*perr = G_STRANGE;
			goto err;
		}

		dprintf("Note hdr n_type=%u n_namesz=%u n_descsz=%u\n",
		    nhdr.n_type, nhdr.n_namesz, nhdr.n_descsz);

		off = lseek64(P->asfd, (off64_t)0L, SEEK_CUR);

		/*
		 * Invoke the note handler function from our table
		 */
		if (nhdr.n_type < sizeof (nhdlrs) / sizeof (nhdlrs[0])) {
			if (nhdlrs[nhdr.n_type](P, nhdr.n_descsz) < 0) {
				dprintf("handler for type %d returned < 0",
				    nhdr.n_type);
				*perr = G_NOTE;
				goto err;
			}
			/*
			 * The presence of either of these notes indicates that
			 * the dump was generated on Linux.
			 */
#ifdef __x86
			if (nhdr.n_type == NT_PRSTATUS ||
			    nhdr.n_type == NT_PRPSINFO)
				from_linux = B_TRUE;
#endif
		} else {
			(void) note_notsup(P, nhdr.n_descsz);
		}

		/*
		 * Seek past the current note data to the next Elf_Nhdr
		 */
		descsz = P2ROUNDUP((off64_t)nhdr.n_descsz, (off64_t)4);
		if (lseek64(P->asfd, off + descsz, SEEK_SET) == (off64_t)-1) {
			dprintf("Pgrab_core: failed to seek to next nhdr\n");
			*perr = G_STRANGE;
			goto err;
		}

		/*
		 * Subtract the size of the header and its data from what
		 * we have left to process.
		 */
		nleft -= sizeof (nhdr) + namesz + descsz;
	}

#ifdef __x86
	if (from_linux) {
		size_t tcount, pid;
		lwp_info_t *lwp;

		P->status.pr_dmodel = core_info->core_dmodel;

		lwp = list_next(&core_info->core_lwp_head);

		pid = P->status.pr_pid;

		for (tcount = 0; tcount < core_info->core_nlwp;
		    tcount++, lwp = list_next(lwp)) {
			dprintf("Linux thread with id %d\n", lwp->lwp_id);

			/*
			 * In the case we don't have a valid psinfo (i.e. pid is
			 * 0, probably because of gdb creating the core) assume
			 * lowest pid count is the first thread (what if the
			 * next thread wraps the pid around?)
			 */
			if (P->status.pr_pid == 0 &&
			    ((pid == 0 && lwp->lwp_id > 0) ||
			    (lwp->lwp_id < pid))) {
				pid = lwp->lwp_id;
			}
		}

		if (P->status.pr_pid != pid) {
			dprintf("No valid pid, setting to %ld\n", (ulong_t)pid);
			P->status.pr_pid = pid;
			P->psinfo.pr_pid = pid;
		}

		/*
		 * Consumers like mdb expect the first thread to actually have
		 * an id of 1, on linux that is actually the pid. Find the the
		 * thread with our process id, and set the id to 1
		 */
		if ((lwp = lwpid2info(P, pid)) == NULL) {
			dprintf("Couldn't find first thread\n");
			*perr = G_STRANGE;
			goto err;
		}

		dprintf("setting representative thread: %d\n", lwp->lwp_id);

		lwp->lwp_id = 1;
		lwp->lwp_status.pr_lwpid = 1;

		/* set representative thread */
		(void) memcpy(&P->status.pr_lwp, &lwp->lwp_status,
		    sizeof (P->status.pr_lwp));
	}
#endif /* __x86 */

	if (nleft != 0) {
		dprintf("Pgrab_core: note section malformed\n");
		*perr = G_STRANGE;
		goto err;
	}

	if ((pagesize = Pgetauxval(P, AT_PAGESZ)) == -1) {
		pagesize = getpagesize();
		dprintf("AT_PAGESZ missing; defaulting to %d\n", pagesize);
	}

	/*
	 * Locate and label the mappings corresponding to the end of the
	 * heap (MA_BREAK) and the base of the stack (MA_STACK).
	 */
	if ((P->status.pr_brkbase != 0 || P->status.pr_brksize != 0) &&
	    (brk_mp = Paddr2mptr(P, P->status.pr_brkbase +
	    P->status.pr_brksize - 1)) != NULL)
		brk_mp->map_pmap.pr_mflags |= MA_BREAK;
	else
		brk_mp = NULL;

	if ((stk_mp = Paddr2mptr(P, P->status.pr_stkbase)) != NULL)
		stk_mp->map_pmap.pr_mflags |= MA_STACK;

	/*
	 * At this point, we have enough information to look for the
	 * executable and open it: we have access to the auxv, a psinfo_t,
	 * and the ability to read from mappings provided by the core file.
	 */
	(void) Pfindexec(P, aout_path, core_exec_open, &aout);
	dprintf("P->execname = \"%s\"\n", P->execname ? P->execname : "NULL");
	execname = P->execname ? P->execname : "a.out";

	/*
	 * Iterate through the sections, looking for the .dynamic and .interp
	 * sections.  If we encounter them, remember their section pointers.
	 */
	for (scn = NULL; (scn = elf_nextscn(aout.e_elf, scn)) != NULL; ) {
		char *sname;

		if ((gelf_getshdr(scn, &shdr) == NULL) ||
		    (sname = elf_strptr(aout.e_elf, aout.e_hdr.e_shstrndx,
		    (size_t)shdr.sh_name)) == NULL)
			continue;

		if (strcmp(sname, ".interp") == 0)
			intp_scn = scn;
	}

	/*
	 * Get the AT_BASE auxv element.  If this is missing (-1), then
	 * we assume this is a statically-linked executable.
	 */
	base_addr = Pgetauxval(P, AT_BASE);

	/*
	 * In order to get librtld_db initialized, we'll need to identify
	 * and name the mapping corresponding to the run-time linker.  The
	 * AT_BASE auxv element tells us the address where it was mapped,
	 * and the .interp section of the executable tells us its path.
	 * If for some reason that doesn't pan out, just use ld.so.1.
	 */
	if (intp_scn != NULL && (dp = elf_getdata(intp_scn, NULL)) != NULL &&
	    dp->d_size != 0) {
		dprintf(".interp = <%s>\n", (char *)dp->d_buf);
		interp = dp->d_buf;

	} else if (base_addr != (uintptr_t)-1L) {
		if (core_info->core_dmodel == PR_MODEL_LP64)
			interp = "/usr/lib/64/ld.so.1";
		else
			interp = "/usr/lib/ld.so.1";

		dprintf(".interp section is missing or could not be read; "
		    "defaulting to %s\n", interp);
	} else
		dprintf("detected statically linked executable\n");

	/*
	 * If we have an AT_BASE element, name the mapping at that address
	 * using the interpreter pathname.  Name the corresponding data
	 * mapping after the interpreter as well.
	 */
	if (base_addr != (uintptr_t)-1L) {
		elf_file_t intf;

		P->map_ldso = core_name_mapping(P, base_addr, interp);

		if (core_elf_open(&intf, interp, ET_DYN, NULL) == 0) {
			rd_loadobj_t rl;
			map_info_t *dmp;

			rl.rl_base = base_addr;
			dmp = core_find_data(P, intf.e_elf, &rl);

			if (dmp != NULL) {
				dprintf("renamed data at %p to %s\n",
				    (void *)rl.rl_data_base, interp);
				(void) strncpy(dmp->map_pmap.pr_mapname,
				    interp, PRMAPSZ);
				dmp->map_pmap.pr_mapname[PRMAPSZ - 1] = '\0';
			}
		}

		core_elf_close(&intf);
	}

	/*
	 * If we have an AT_ENTRY element, name the mapping at that address
	 * using the special name "a.out" just like /proc does.
	 */
	if ((addr = Pgetauxval(P, AT_ENTRY)) != (uintptr_t)-1L)
		P->map_exec = core_name_mapping(P, addr, "a.out");

	/*
	 * If we're a statically linked executable (or we're on x86 and looking
	 * at a Linux core dump), then just locate the executable's text and
	 * data and name them after the executable.
	 */
#ifndef __x86
	if (base_addr == (uintptr_t)-1L) {
#else
	if (base_addr == (uintptr_t)-1L || from_linux) {
#endif
		dprintf("looking for text and data: %s\n", execname);
		map_info_t *tmp, *dmp;
		file_info_t *fp;
		rd_loadobj_t rl;

		if ((tmp = core_find_text(P, aout.e_elf, &rl)) != NULL &&
		    (dmp = core_find_data(P, aout.e_elf, &rl)) != NULL) {
			(void) strncpy(tmp->map_pmap.pr_mapname,
			    execname, PRMAPSZ);
			tmp->map_pmap.pr_mapname[PRMAPSZ - 1] = '\0';
			(void) strncpy(dmp->map_pmap.pr_mapname,
			    execname, PRMAPSZ);
			dmp->map_pmap.pr_mapname[PRMAPSZ - 1] = '\0';
		}

		if ((P->map_exec = tmp) != NULL &&
		    (fp = malloc(sizeof (file_info_t))) != NULL) {

			(void) memset(fp, 0, sizeof (file_info_t));

			list_link(fp, &P->file_head);
			tmp->map_file = fp;
			P->num_files++;

			fp->file_ref = 1;
			fp->file_fd = -1;

			fp->file_lo = malloc(sizeof (rd_loadobj_t));
			fp->file_lname = strdup(execname);

			if (fp->file_lo)
				*fp->file_lo = rl;
			if (fp->file_lname)
				fp->file_lbase = basename(fp->file_lname);
			if (fp->file_rname)
				fp->file_rbase = basename(fp->file_rname);

			(void) strcpy(fp->file_pname,
			    P->mappings[0].map_pmap.pr_mapname);
			fp->file_map = tmp;

			Pbuild_file_symtab(P, fp);

			if (dmp != NULL) {
				dmp->map_file = fp;
				fp->file_ref++;
			}
		}
	}

	core_elf_close(&aout);

	/*
	 * We now have enough information to initialize librtld_db.
	 * After it warms up, we can iterate through the load object chain
	 * in the core, which will allow us to construct the file info
	 * we need to provide symbol information for the other shared
	 * libraries, and also to fill in the missing mapping names.
	 */
	rd_log(_libproc_debug);

	if ((P->rap = rd_new(P)) != NULL) {
		(void) rd_loadobj_iter(P->rap, (rl_iter_f *)
		    core_iter_mapping, P);

		if (core_info->core_errno != 0) {
			errno = core_info->core_errno;
			*perr = G_STRANGE;
			goto err;
		}
	} else
		dprintf("failed to initialize rtld_db agent\n");

	/*
	 * If there are sections, load them and process the data from any
	 * sections that we can use to annotate the file_info_t's.
	 */
	core_load_shdrs(P, &core);

	/*
	 * If we previously located a stack or break mapping, and they are
	 * still anonymous, we now assume that they were MAP_ANON mappings.
	 * If brk_mp turns out to now have a name, then the heap is still
	 * sitting at the end of the executable's data+bss mapping: remove
	 * the previous MA_BREAK setting to be consistent with /proc.
	 */
	if (stk_mp != NULL && stk_mp->map_pmap.pr_mapname[0] == '\0')
		stk_mp->map_pmap.pr_mflags |= MA_ANON;
	if (brk_mp != NULL && brk_mp->map_pmap.pr_mapname[0] == '\0')
		brk_mp->map_pmap.pr_mflags |= MA_ANON;
	else if (brk_mp != NULL)
		brk_mp->map_pmap.pr_mflags &= ~MA_BREAK;

	*perr = 0;
	return (P);

err:
	Pfree(P);
	core_elf_close(&aout);
	return (NULL);
}

/*
 * Grab a core file using a pathname.  We just open it and call Pfgrab_core().
 */
struct ps_prochandle *
Pgrab_core(const char *core, const char *aout, int gflag, int *perr)
{
	int fd, oflag = (gflag & PGRAB_RDONLY) ? O_RDONLY : O_RDWR;

	if ((fd = open64(core, oflag)) >= 0)
		return (Pfgrab_core(fd, aout, perr));

	if (errno != ENOENT)
		*perr = G_STRANGE;
	else
		*perr = G_NOCORE;

	return (NULL);
}
