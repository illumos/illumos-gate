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
 * Copyright 2015 Joyent, Inc.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#define	_STRUCTURED_PROC	1

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <procfs.h>
#include <priv.h>
#include <sys/elf.h>
#include <sys/machelf.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/proc.h>
#include <sys/utsname.h>

#include <sys/old_procfs.h>

#include "Pcontrol.h"
#include "P32ton.h"

typedef enum {
	STR_NONE,
	STR_CTF,
	STR_SYMTAB,
	STR_DYNSYM,
	STR_STRTAB,
	STR_DYNSTR,
	STR_SHSTRTAB,
	STR_NUM
} shstrtype_t;

static const char *shstrtab_data[] = {
	"",
	".SUNW_ctf",
	".symtab",
	".dynsym",
	".strtab",
	".dynstr",
	".shstrtab"
};

typedef struct shstrtab {
	int	sst_ndx[STR_NUM];
	int	sst_cur;
} shstrtab_t;

typedef struct {
	struct ps_prochandle *P;
	int		pgc_fd;
	off64_t		*pgc_poff;
	off64_t		*pgc_soff;
	off64_t		*pgc_doff;
	core_content_t	pgc_content;
	void		*pgc_chunk;
	size_t		pgc_chunksz;

	shstrtab_t	pgc_shstrtab;
} pgcore_t;

typedef struct {
	int		fd_fd;
	off64_t		*fd_doff;
} fditer_t;

static int
gc_pwrite64(int fd, const void *buf, size_t len, off64_t off)
{
	int err;

	err = pwrite64(fd, buf, len, off);

	if (err < 0)
		return (err);

	/*
	 * We will take a page from ZFS's book here and use the otherwise
	 * unused EBADE to mean a short write.  Typically this will actually
	 * result from ENOSPC or EDQUOT, but we can't be sure.
	 */
	if (err < len) {
		errno = EBADE;
		return (-1);
	}

	return (0);
}

static void
shstrtab_init(shstrtab_t *s)
{
	bzero(&s->sst_ndx, sizeof (s->sst_ndx));
	s->sst_cur = 1;
}

static int
shstrtab_ndx(shstrtab_t *s, shstrtype_t type)
{
	int ret;

	if ((ret = s->sst_ndx[type]) != 0 || type == STR_NONE)
		return (ret);

	ret = s->sst_ndx[type] = s->sst_cur;
	s->sst_cur += strlen(shstrtab_data[type]) + 1;

	return (ret);
}

static size_t
shstrtab_size(const shstrtab_t *s)
{
	return (s->sst_cur);
}

int
Pgcore(struct ps_prochandle *P, const char *fname, core_content_t content)
{
	int fd;
	int err;
	int saved_errno;

	if ((fd = creat64(fname, 0666)) < 0)
		return (-1);

	if ((err = Pfgcore(P, fd, content)) != 0) {
		saved_errno = errno;
		(void) close(fd);
		(void) unlink(fname);
		errno = saved_errno;
		return (err);
	}

	return (close(fd));
}

/*
 * Since we don't want to use the old-school procfs interfaces, we use the
 * new-style data structures we already have to construct the old-style
 * data structures. We include these data structures in core files for
 * backward compatability.
 */

static void
mkprstatus(struct ps_prochandle *P, const lwpstatus_t *lsp,
    const lwpsinfo_t *lip, prstatus_t *psp)
{
	bzero(psp, sizeof (*psp));

	if (lsp->pr_flags & PR_STOPPED)
		psp->pr_flags = 0x0001;
	if (lsp->pr_flags & PR_ISTOP)
		psp->pr_flags = 0x0002;
	if (lsp->pr_flags & PR_DSTOP)
		psp->pr_flags = 0x0004;
	if (lsp->pr_flags & PR_ASLEEP)
		psp->pr_flags = 0x0008;
	if (lsp->pr_flags & PR_FORK)
		psp->pr_flags = 0x0010;
	if (lsp->pr_flags & PR_RLC)
		psp->pr_flags = 0x0020;
	/*
	 * Note that PR_PTRACE (0x0040) from <sys/old_procfs.h> is never set;
	 * PR_PCOMPAT corresponds to PR_PTRACE in the newer <sys/procfs.h>.
	 */
	if (lsp->pr_flags & PR_PCINVAL)
		psp->pr_flags = 0x0080;
	if (lsp->pr_flags & PR_ISSYS)
		psp->pr_flags = 0x0100;
	if (lsp->pr_flags & PR_STEP)
		psp->pr_flags = 0x0200;
	if (lsp->pr_flags & PR_KLC)
		psp->pr_flags = 0x0400;
	if (lsp->pr_flags & PR_ASYNC)
		psp->pr_flags = 0x0800;
	if (lsp->pr_flags & PR_PTRACE)
		psp->pr_flags = 0x1000;
	if (lsp->pr_flags & PR_MSACCT)
		psp->pr_flags = 0x2000;
	if (lsp->pr_flags & PR_BPTADJ)
		psp->pr_flags = 0x4000;
	if (lsp->pr_flags & PR_ASLWP)
		psp->pr_flags = 0x8000;

	psp->pr_why = lsp->pr_why;
	psp->pr_what = lsp->pr_what;
	psp->pr_info = lsp->pr_info;
	psp->pr_cursig = lsp->pr_cursig;
	psp->pr_nlwp = P->status.pr_nlwp;
	psp->pr_sigpend = P->status.pr_sigpend;
	psp->pr_sighold = lsp->pr_lwphold;
	psp->pr_altstack = lsp->pr_altstack;
	psp->pr_action = lsp->pr_action;
	psp->pr_pid = P->status.pr_pid;
	psp->pr_ppid = P->status.pr_ppid;
	psp->pr_pgrp = P->status.pr_pgid;
	psp->pr_sid = P->status.pr_sid;
	psp->pr_utime = P->status.pr_utime;
	psp->pr_stime = P->status.pr_stime;
	psp->pr_cutime = P->status.pr_cutime;
	psp->pr_cstime = P->status.pr_cstime;
	(void) strncpy(psp->pr_clname, lsp->pr_clname, sizeof (psp->pr_clname));
	psp->pr_syscall = lsp->pr_syscall;
	psp->pr_nsysarg = lsp->pr_nsysarg;
	bcopy(lsp->pr_sysarg, psp->pr_sysarg, sizeof (psp->pr_sysarg));
	psp->pr_who = lsp->pr_lwpid;
	psp->pr_lwppend = lsp->pr_lwppend;
	psp->pr_oldcontext = (ucontext_t *)lsp->pr_oldcontext;
	psp->pr_brkbase = (caddr_t)P->status.pr_brkbase;
	psp->pr_brksize = P->status.pr_brksize;
	psp->pr_stkbase = (caddr_t)P->status.pr_stkbase;
	psp->pr_stksize = P->status.pr_stksize;
	psp->pr_processor = (short)lip->pr_onpro;
	psp->pr_bind = (short)lip->pr_bindpro;
	psp->pr_instr = lsp->pr_instr;
	bcopy(lsp->pr_reg, psp->pr_reg, sizeof (psp->pr_sysarg));
}

static void
mkprpsinfo(struct ps_prochandle *P, prpsinfo_t *psp)
{
	bzero(psp, sizeof (*psp));
	psp->pr_state = P->psinfo.pr_lwp.pr_state;
	psp->pr_sname = P->psinfo.pr_lwp.pr_sname;
	psp->pr_zomb = (psp->pr_state == SZOMB);
	psp->pr_nice = P->psinfo.pr_lwp.pr_nice;
	psp->pr_flag = P->psinfo.pr_lwp.pr_flag;
	psp->pr_uid = P->psinfo.pr_uid;
	psp->pr_gid = P->psinfo.pr_gid;
	psp->pr_pid = P->psinfo.pr_pid;
	psp->pr_ppid = P->psinfo.pr_ppid;
	psp->pr_pgrp = P->psinfo.pr_pgid;
	psp->pr_sid = P->psinfo.pr_sid;
	psp->pr_addr = (caddr_t)P->psinfo.pr_addr;
	psp->pr_size = P->psinfo.pr_size;
	psp->pr_rssize = P->psinfo.pr_rssize;
	psp->pr_wchan = (caddr_t)P->psinfo.pr_lwp.pr_wchan;
	psp->pr_start = P->psinfo.pr_start;
	psp->pr_time = P->psinfo.pr_time;
	psp->pr_pri = P->psinfo.pr_lwp.pr_pri;
	psp->pr_oldpri = P->psinfo.pr_lwp.pr_oldpri;
	psp->pr_cpu = P->psinfo.pr_lwp.pr_cpu;
	psp->pr_ottydev = cmpdev(P->psinfo.pr_ttydev);
	psp->pr_lttydev = P->psinfo.pr_ttydev;
	(void) strncpy(psp->pr_clname, P->psinfo.pr_lwp.pr_clname,
	    sizeof (psp->pr_clname));
	(void) strncpy(psp->pr_fname, P->psinfo.pr_fname,
	    sizeof (psp->pr_fname));
	bcopy(&P->psinfo.pr_psargs, &psp->pr_psargs,
	    sizeof (psp->pr_psargs));
	psp->pr_syscall = P->psinfo.pr_lwp.pr_syscall;
	psp->pr_ctime = P->psinfo.pr_ctime;
	psp->pr_bysize = psp->pr_size * PAGESIZE;
	psp->pr_byrssize = psp->pr_rssize * PAGESIZE;
	psp->pr_argc = P->psinfo.pr_argc;
	psp->pr_argv = (char **)P->psinfo.pr_argv;
	psp->pr_envp = (char **)P->psinfo.pr_envp;
	psp->pr_wstat = P->psinfo.pr_wstat;
	psp->pr_pctcpu = P->psinfo.pr_pctcpu;
	psp->pr_pctmem = P->psinfo.pr_pctmem;
	psp->pr_euid = P->psinfo.pr_euid;
	psp->pr_egid = P->psinfo.pr_egid;
	psp->pr_aslwpid = 0;
	psp->pr_dmodel = P->psinfo.pr_dmodel;
}

#ifdef _LP64

static void
mkprstatus32(struct ps_prochandle *P, const lwpstatus_t *lsp,
    const lwpsinfo_t *lip, prstatus32_t *psp)
{
	bzero(psp, sizeof (*psp));

	if (lsp->pr_flags & PR_STOPPED)
		psp->pr_flags = 0x0001;
	if (lsp->pr_flags & PR_ISTOP)
		psp->pr_flags = 0x0002;
	if (lsp->pr_flags & PR_DSTOP)
		psp->pr_flags = 0x0004;
	if (lsp->pr_flags & PR_ASLEEP)
		psp->pr_flags = 0x0008;
	if (lsp->pr_flags & PR_FORK)
		psp->pr_flags = 0x0010;
	if (lsp->pr_flags & PR_RLC)
		psp->pr_flags = 0x0020;
	/*
	 * Note that PR_PTRACE (0x0040) from <sys/old_procfs.h> is never set;
	 * PR_PCOMPAT corresponds to PR_PTRACE in the newer <sys/procfs.h>.
	 */
	if (lsp->pr_flags & PR_PCINVAL)
		psp->pr_flags = 0x0080;
	if (lsp->pr_flags & PR_ISSYS)
		psp->pr_flags = 0x0100;
	if (lsp->pr_flags & PR_STEP)
		psp->pr_flags = 0x0200;
	if (lsp->pr_flags & PR_KLC)
		psp->pr_flags = 0x0400;
	if (lsp->pr_flags & PR_ASYNC)
		psp->pr_flags = 0x0800;
	if (lsp->pr_flags & PR_PTRACE)
		psp->pr_flags = 0x1000;
	if (lsp->pr_flags & PR_MSACCT)
		psp->pr_flags = 0x2000;
	if (lsp->pr_flags & PR_BPTADJ)
		psp->pr_flags = 0x4000;
	if (lsp->pr_flags & PR_ASLWP)
		psp->pr_flags = 0x8000;

	psp->pr_why = lsp->pr_why;
	psp->pr_what = lsp->pr_what;
	siginfo_n_to_32(&lsp->pr_info, &psp->pr_info);
	psp->pr_cursig = lsp->pr_cursig;
	psp->pr_nlwp = P->status.pr_nlwp;
	psp->pr_sigpend = P->status.pr_sigpend;
	psp->pr_sighold = lsp->pr_lwphold;
	stack_n_to_32(&lsp->pr_altstack, &psp->pr_altstack);
	sigaction_n_to_32(&lsp->pr_action, &psp->pr_action);
	psp->pr_pid = P->status.pr_pid;
	psp->pr_ppid = P->status.pr_ppid;
	psp->pr_pgrp = P->status.pr_pgid;
	psp->pr_sid = P->status.pr_sid;
	timestruc_n_to_32(&P->status.pr_utime, &psp->pr_utime);
	timestruc_n_to_32(&P->status.pr_stime, &psp->pr_stime);
	timestruc_n_to_32(&P->status.pr_cutime, &psp->pr_cutime);
	timestruc_n_to_32(&P->status.pr_cstime, &psp->pr_cstime);
	(void) strncpy(psp->pr_clname, lsp->pr_clname, sizeof (psp->pr_clname));
	psp->pr_syscall = lsp->pr_syscall;
	psp->pr_nsysarg = lsp->pr_nsysarg;
	bcopy(lsp->pr_sysarg, psp->pr_sysarg, sizeof (psp->pr_sysarg));
	psp->pr_who = lsp->pr_lwpid;
	psp->pr_lwppend = lsp->pr_lwppend;
	psp->pr_oldcontext = (caddr32_t)lsp->pr_oldcontext;
	psp->pr_brkbase = (caddr32_t)P->status.pr_brkbase;
	psp->pr_brksize = P->status.pr_brksize;
	psp->pr_stkbase = (caddr32_t)P->status.pr_stkbase;
	psp->pr_stksize = P->status.pr_stksize;
	psp->pr_processor = (short)lip->pr_onpro;
	psp->pr_bind = (short)lip->pr_bindpro;
	psp->pr_instr = lsp->pr_instr;
	bcopy(lsp->pr_reg, psp->pr_reg, sizeof (psp->pr_sysarg));
}

static void
mkprpsinfo32(struct ps_prochandle *P, prpsinfo32_t *psp)
{
	bzero(psp, sizeof (*psp));
	psp->pr_state = P->psinfo.pr_lwp.pr_state;
	psp->pr_sname = P->psinfo.pr_lwp.pr_sname;
	psp->pr_zomb = (psp->pr_state == SZOMB);
	psp->pr_nice = P->psinfo.pr_lwp.pr_nice;
	psp->pr_flag = P->psinfo.pr_lwp.pr_flag;
	psp->pr_uid = P->psinfo.pr_uid;
	psp->pr_gid = P->psinfo.pr_gid;
	psp->pr_pid = P->psinfo.pr_pid;
	psp->pr_ppid = P->psinfo.pr_ppid;
	psp->pr_pgrp = P->psinfo.pr_pgid;
	psp->pr_sid = P->psinfo.pr_sid;
	psp->pr_addr = (caddr32_t)P->psinfo.pr_addr;
	psp->pr_size = P->psinfo.pr_size;
	psp->pr_rssize = P->psinfo.pr_rssize;
	psp->pr_wchan = (caddr32_t)P->psinfo.pr_lwp.pr_wchan;
	timestruc_n_to_32(&P->psinfo.pr_start, &psp->pr_start);
	timestruc_n_to_32(&P->psinfo.pr_time, &psp->pr_time);
	psp->pr_pri = P->psinfo.pr_lwp.pr_pri;
	psp->pr_oldpri = P->psinfo.pr_lwp.pr_oldpri;
	psp->pr_cpu = P->psinfo.pr_lwp.pr_cpu;
	psp->pr_ottydev = cmpdev(P->psinfo.pr_ttydev);
	psp->pr_lttydev = prcmpldev(P->psinfo.pr_ttydev);
	(void) strncpy(psp->pr_clname, P->psinfo.pr_lwp.pr_clname,
	    sizeof (psp->pr_clname));
	(void) strncpy(psp->pr_fname, P->psinfo.pr_fname,
	    sizeof (psp->pr_fname));
	bcopy(&P->psinfo.pr_psargs, &psp->pr_psargs,
	    sizeof (psp->pr_psargs));
	psp->pr_syscall = P->psinfo.pr_lwp.pr_syscall;
	timestruc_n_to_32(&P->psinfo.pr_ctime, &psp->pr_ctime);
	psp->pr_bysize = psp->pr_size * PAGESIZE;
	psp->pr_byrssize = psp->pr_rssize * PAGESIZE;
	psp->pr_argc = P->psinfo.pr_argc;
	psp->pr_argv = (caddr32_t)P->psinfo.pr_argv;
	psp->pr_envp = (caddr32_t)P->psinfo.pr_envp;
	psp->pr_wstat = P->psinfo.pr_wstat;
	psp->pr_pctcpu = P->psinfo.pr_pctcpu;
	psp->pr_pctmem = P->psinfo.pr_pctmem;
	psp->pr_euid = P->psinfo.pr_euid;
	psp->pr_egid = P->psinfo.pr_egid;
	psp->pr_aslwpid = 0;
	psp->pr_dmodel = P->psinfo.pr_dmodel;
}

#endif	/* _LP64 */

static int
write_note(int fd, uint_t type, const void *desc, size_t descsz, off64_t *offp)
{
	/*
	 * Note headers are the same regardless of the data model of the
	 * ELF file; we arbitrarily use Elf64_Nhdr here.
	 */
	struct {
		Elf64_Nhdr nhdr;
		char name[8];
	} n;

	bzero(&n, sizeof (n));
	bcopy("CORE", n.name, 4);
	n.nhdr.n_type = type;
	n.nhdr.n_namesz = 5;
	n.nhdr.n_descsz = roundup(descsz, 4);

	if (gc_pwrite64(fd, &n, sizeof (n), *offp) != 0)
		return (-1);

	*offp += sizeof (n);

	if (gc_pwrite64(fd, desc, n.nhdr.n_descsz, *offp) != 0)
		return (-1);

	*offp += n.nhdr.n_descsz;

	return (0);
}

static int
old_per_lwp(void *data, const lwpstatus_t *lsp, const lwpsinfo_t *lip)
{
	pgcore_t *pgc = data;
	struct ps_prochandle *P = pgc->P;

	/*
	 * Legacy core files don't contain information about zombie LWPs.
	 * We use Plwp_iter_all() so that we get the lwpsinfo_t structure
	 * more cheaply.
	 */
	if (lsp == NULL)
		return (0);

	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		prstatus_t prstatus;
		mkprstatus(P, lsp, lip, &prstatus);
		if (write_note(pgc->pgc_fd, NT_PRSTATUS, &prstatus,
		    sizeof (prstatus_t), pgc->pgc_doff) != 0)
			return (0);
		if (write_note(pgc->pgc_fd, NT_PRFPREG, &lsp->pr_fpreg,
		    sizeof (prfpregset_t), pgc->pgc_doff) != 0)
			return (1);
#ifdef _LP64
	} else {
		prstatus32_t pr32;
		prfpregset32_t pf32;
		mkprstatus32(P, lsp, lip, &pr32);
		if (write_note(pgc->pgc_fd, NT_PRSTATUS, &pr32,
		    sizeof (prstatus32_t), pgc->pgc_doff) != 0)
			return (1);
		prfpregset_n_to_32(&lsp->pr_fpreg, &pf32);
		if (write_note(pgc->pgc_fd, NT_PRFPREG, &pf32,
		    sizeof (prfpregset32_t), pgc->pgc_doff) != 0)
			return (1);
#endif	/* _LP64 */
	}

#ifdef sparc
	{
		prxregset_t xregs;
		if (Plwp_getxregs(P, lsp->pr_lwpid, &xregs) == 0 &&
		    write_note(pgc->pgc_fd, NT_PRXREG, &xregs,
		    sizeof (prxregset_t), pgc->pgc_doff) != 0)
			return (1);
	}
#endif	/* sparc */

	return (0);
}

static int
new_per_lwp(void *data, const lwpstatus_t *lsp, const lwpsinfo_t *lip)
{
	pgcore_t *pgc = data;
	struct ps_prochandle *P = pgc->P;
	psinfo_t ps;

	/*
	 * If lsp is NULL this indicates that this is a zombie LWP in
	 * which case we dump only the lwpsinfo_t structure and none of
	 * the other ancillary LWP state data.
	 */
	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		if (write_note(pgc->pgc_fd, NT_LWPSINFO, lip,
		    sizeof (lwpsinfo_t), pgc->pgc_doff) != 0)
			return (1);
		if (lsp == NULL)
			return (0);
		if (write_note(pgc->pgc_fd, NT_LWPSTATUS, lsp,
		    sizeof (lwpstatus_t), pgc->pgc_doff) != 0)
			return (1);
#ifdef _LP64
	} else {
		lwpsinfo32_t li32;
		lwpstatus32_t ls32;
		lwpsinfo_n_to_32(lip, &li32);
		if (write_note(pgc->pgc_fd, NT_LWPSINFO, &li32,
		    sizeof (lwpsinfo32_t), pgc->pgc_doff) != 0)
			return (1);
		if (lsp == NULL)
			return (0);
		lwpstatus_n_to_32(lsp, &ls32);
		if (write_note(pgc->pgc_fd, NT_LWPSTATUS, &ls32,
		    sizeof (lwpstatus32_t), pgc->pgc_doff) != 0)
			return (1);
#endif	/* _LP64 */
	}

#ifdef sparc
	{
		prxregset_t xregs;
		gwindows_t gwins;
		size_t size;

		if (Plwp_getxregs(P, lsp->pr_lwpid, &xregs) == 0) {
			if (write_note(pgc->pgc_fd, NT_PRXREG, &xregs,
			    sizeof (prxregset_t), pgc->pgc_doff) != 0)
				return (1);
		}

		if (Plwp_getgwindows(P, lsp->pr_lwpid, &gwins) == 0 &&
		    gwins.wbcnt > 0) {
			size = sizeof (gwins) - sizeof (gwins.wbuf) +
			    gwins.wbcnt * sizeof (gwins.wbuf[0]);

			if (write_note(pgc->pgc_fd, NT_GWINDOWS, &gwins, size,
			    pgc->pgc_doff) != 0)
				return (1);
		}

	}
#ifdef __sparcv9
	if (P->status.pr_dmodel == PR_MODEL_LP64) {
		asrset_t asrs;
		if (Plwp_getasrs(P, lsp->pr_lwpid, asrs) == 0) {
			if (write_note(pgc->pgc_fd, NT_ASRS, &asrs,
			    sizeof (asrset_t), pgc->pgc_doff) != 0)
				return (1);
		}
	}
#endif	/* __sparcv9 */
#endif	/* sparc */

	if (!(lsp->pr_flags & PR_AGENT))
		return (0);

	if (Plwp_getspymaster(P, lsp->pr_lwpid, &ps) != 0)
		return (0);

	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		if (write_note(pgc->pgc_fd, NT_SPYMASTER, &ps,
		    sizeof (psinfo_t), pgc->pgc_doff) != 0)
			return (1);
#ifdef _LP64
	} else {
		psinfo32_t ps32;
		psinfo_n_to_32(&ps, &ps32);
		if (write_note(pgc->pgc_fd, NT_SPYMASTER, &ps32,
		    sizeof (psinfo32_t), pgc->pgc_doff) != 0)
			return (1);
#endif	/* _LP64 */
	}


	return (0);
}

static int
iter_fd(void *data, prfdinfo_t *fdinfo)
{
	fditer_t *iter = data;

	if (write_note(iter->fd_fd, NT_FDINFO, fdinfo,
	    sizeof (*fdinfo), iter->fd_doff) != 0)
		return (1);
	return (0);
}

static uint_t
count_sections(pgcore_t *pgc)
{
	struct ps_prochandle *P = pgc->P;
	file_info_t *fptr;
	uint_t cnt;
	uint_t nshdrs = 0;

	if (!(pgc->pgc_content & (CC_CONTENT_CTF | CC_CONTENT_SYMTAB)))
		return (0);

	fptr = list_next(&P->file_head);
	for (cnt = P->num_files; cnt > 0; cnt--, fptr = list_next(fptr)) {
		int hit_symtab = 0;

		Pbuild_file_symtab(P, fptr);

		if ((pgc->pgc_content & CC_CONTENT_CTF) &&
		    Pbuild_file_ctf(P, fptr) != NULL) {
			sym_tbl_t *sym;

			nshdrs++;

			if (fptr->file_ctf_dyn) {
				sym = &fptr->file_dynsym;
			} else {
				sym = &fptr->file_symtab;
				hit_symtab = 1;
			}

			if (sym->sym_data_pri != NULL && sym->sym_symn != 0 &&
			    sym->sym_strs != NULL)
				nshdrs += 2;
		}

		if ((pgc->pgc_content & CC_CONTENT_SYMTAB) && !hit_symtab &&
		    fptr->file_symtab.sym_data_pri != NULL &&
		    fptr->file_symtab.sym_symn != 0 &&
		    fptr->file_symtab.sym_strs != NULL) {
			nshdrs += 2;
		}
	}

	return (nshdrs == 0 ? 0 : nshdrs + 2);
}

static int
write_shdr(pgcore_t *pgc, shstrtype_t name, uint_t type, ulong_t flags,
    uintptr_t addr, ulong_t offset, size_t size, uint_t link, uint_t info,
    uintptr_t addralign, uintptr_t entsize)
{
	if (pgc->P->status.pr_dmodel == PR_MODEL_ILP32) {
		Elf32_Shdr shdr;

		bzero(&shdr, sizeof (shdr));
		shdr.sh_name = shstrtab_ndx(&pgc->pgc_shstrtab, name);
		shdr.sh_type = type;
		shdr.sh_flags = flags;
		shdr.sh_addr = (Elf32_Addr)addr;
		shdr.sh_offset = offset;
		shdr.sh_size = size;
		shdr.sh_link = link;
		shdr.sh_info = info;
		shdr.sh_addralign = addralign;
		shdr.sh_entsize = entsize;

		if (gc_pwrite64(pgc->pgc_fd, &shdr, sizeof (shdr),
		    *pgc->pgc_soff) != 0)
			return (-1);

		*pgc->pgc_soff += sizeof (shdr);
#ifdef _LP64
	} else {
		Elf64_Shdr shdr;

		bzero(&shdr, sizeof (shdr));
		shdr.sh_name = shstrtab_ndx(&pgc->pgc_shstrtab, name);
		shdr.sh_type = type;
		shdr.sh_flags = flags;
		shdr.sh_addr = addr;
		shdr.sh_offset = offset;
		shdr.sh_size = size;
		shdr.sh_link = link;
		shdr.sh_info = info;
		shdr.sh_addralign = addralign;
		shdr.sh_entsize = entsize;

		if (gc_pwrite64(pgc->pgc_fd, &shdr, sizeof (shdr),
		    *pgc->pgc_soff) != 0)
			return (-1);

		*pgc->pgc_soff += sizeof (shdr);
#endif	/* _LP64 */
	}

	return (0);
}

static int
dump_symtab(pgcore_t *pgc, file_info_t *fptr, uint_t index, int dynsym)
{
	sym_tbl_t *sym = dynsym ? &fptr->file_dynsym : &fptr->file_symtab;
	shstrtype_t symname = dynsym ? STR_DYNSYM : STR_SYMTAB;
	shstrtype_t strname = dynsym ? STR_DYNSTR : STR_STRTAB;
	uint_t symtype = dynsym ? SHT_DYNSYM : SHT_SYMTAB;
	size_t size;
	uintptr_t addr = fptr->file_map->map_pmap.pr_vaddr;

	if (sym->sym_data_pri == NULL || sym->sym_symn == 0 ||
	    sym->sym_strs == NULL)
		return (0);

	size = sym->sym_hdr_pri.sh_size;
	if (gc_pwrite64(pgc->pgc_fd, sym->sym_data_pri->d_buf, size,
	    *pgc->pgc_doff) != 0)
		return (-1);

	if (write_shdr(pgc, symname, symtype, 0, addr, *pgc->pgc_doff, size,
	    index + 1, sym->sym_hdr_pri.sh_info, sym->sym_hdr_pri.sh_addralign,
	    sym->sym_hdr_pri.sh_entsize) != 0)
		return (-1);

	*pgc->pgc_doff += roundup(size, 8);

	size = sym->sym_strhdr.sh_size;
	if (gc_pwrite64(pgc->pgc_fd, sym->sym_strs, size, *pgc->pgc_doff) != 0)
		return (-1);

	if (write_shdr(pgc, strname, SHT_STRTAB, SHF_STRINGS, addr,
	    *pgc->pgc_doff, size, 0, 0, 1, 0) != 0)
		return (-1);

	*pgc->pgc_doff += roundup(size, 8);

	return (0);
}

static int
dump_sections(pgcore_t *pgc)
{
	struct ps_prochandle *P = pgc->P;
	file_info_t *fptr;
	uint_t cnt;
	uint_t index = 1;

	if (!(pgc->pgc_content & (CC_CONTENT_CTF | CC_CONTENT_SYMTAB)))
		return (0);

	fptr = list_next(&P->file_head);
	for (cnt = P->num_files; cnt > 0; cnt--, fptr = list_next(fptr)) {
		int hit_symtab = 0;

		Pbuild_file_symtab(P, fptr);

		if ((pgc->pgc_content & CC_CONTENT_CTF) &&
		    Pbuild_file_ctf(P, fptr) != NULL) {
			sym_tbl_t *sym;
			uint_t dynsym;
			uint_t symindex = 0;

			/*
			 * Write the symtab out first so we can correctly
			 * set the sh_link field in the CTF section header.
			 * symindex will be 0 if there is no corresponding
			 * symbol table section.
			 */
			if (fptr->file_ctf_dyn) {
				sym = &fptr->file_dynsym;
				dynsym = 1;
			} else {
				sym = &fptr->file_symtab;
				dynsym = 0;
				hit_symtab = 1;
			}

			if (sym->sym_data_pri != NULL && sym->sym_symn != 0 &&
			    sym->sym_strs != NULL) {
				symindex = index;
				if (dump_symtab(pgc, fptr, index, dynsym) != 0)
					return (-1);
				index += 2;
			}

			/*
			 * Write the CTF data that we've read out of the
			 * file itself into the core file.
			 */
			if (gc_pwrite64(pgc->pgc_fd, fptr->file_ctf_buf,
			    fptr->file_ctf_size, *pgc->pgc_doff) != 0)
				return (-1);

			if (write_shdr(pgc, STR_CTF, SHT_PROGBITS, 0,
			    fptr->file_map->map_pmap.pr_vaddr, *pgc->pgc_doff,
			    fptr->file_ctf_size, symindex, 0, 4, 0) != 0)
				return (-1);

			index++;
			*pgc->pgc_doff += roundup(fptr->file_ctf_size, 8);
		}

		if ((pgc->pgc_content & CC_CONTENT_SYMTAB) && !hit_symtab &&
		    fptr->file_symtab.sym_data_pri != NULL &&
		    fptr->file_symtab.sym_symn != 0 &&
		    fptr->file_symtab.sym_strs != NULL) {
			if (dump_symtab(pgc, fptr, index, 0) != 0)
				return (-1);
			index += 2;
		}
	}

	return (0);
}

/*ARGSUSED*/
static int
dump_map(void *data, const prmap_t *pmp, const char *name)
{
	pgcore_t *pgc = data;
	struct ps_prochandle *P = pgc->P;
#ifdef _LP64
	Elf64_Phdr phdr;
#else
	Elf32_Phdr phdr;
#endif
	size_t n;

	bzero(&phdr, sizeof (phdr));
	phdr.p_type = PT_LOAD;
	phdr.p_vaddr = pmp->pr_vaddr;
	phdr.p_memsz = pmp->pr_size;
	if (pmp->pr_mflags & MA_READ)
		phdr.p_flags |= PF_R;
	if (pmp->pr_mflags & MA_WRITE)
		phdr.p_flags |= PF_W;
	if (pmp->pr_mflags & MA_EXEC)
		phdr.p_flags |= PF_X;

	if (pmp->pr_vaddr + pmp->pr_size > P->status.pr_stkbase &&
	    pmp->pr_vaddr < P->status.pr_stkbase + P->status.pr_stksize) {
		if (!(pgc->pgc_content & CC_CONTENT_STACK))
			goto exclude;

	} else if ((pmp->pr_mflags & MA_ANON) &&
	    pmp->pr_vaddr + pmp->pr_size > P->status.pr_brkbase &&
	    pmp->pr_vaddr < P->status.pr_brkbase + P->status.pr_brksize) {
		if (!(pgc->pgc_content & CC_CONTENT_HEAP))
			goto exclude;

	} else if (pmp->pr_mflags & MA_ISM) {
		if (pmp->pr_mflags & MA_NORESERVE) {
			if (!(pgc->pgc_content & CC_CONTENT_DISM))
				goto exclude;
		} else {
			if (!(pgc->pgc_content & CC_CONTENT_ISM))
				goto exclude;
		}

	} else if (pmp->pr_mflags & MA_SHM) {
		if (!(pgc->pgc_content & CC_CONTENT_SHM))
			goto exclude;

	} else if (pmp->pr_mflags & MA_SHARED) {
		if (pmp->pr_mflags & MA_ANON) {
			if (!(pgc->pgc_content & CC_CONTENT_SHANON))
				goto exclude;
		} else {
			if (!(pgc->pgc_content & CC_CONTENT_SHFILE))
				goto exclude;
		}

	} else if (pmp->pr_mflags & MA_ANON) {
		if (!(pgc->pgc_content & CC_CONTENT_ANON))
			goto exclude;

	} else if (phdr.p_flags == (PF_R | PF_X)) {
		if (!(pgc->pgc_content & CC_CONTENT_TEXT))
			goto exclude;

	} else if (phdr.p_flags == PF_R) {
		if (!(pgc->pgc_content & CC_CONTENT_RODATA))
			goto exclude;

	} else {
		if (!(pgc->pgc_content & CC_CONTENT_DATA))
			goto exclude;
	}

	n = 0;
	while (n < pmp->pr_size) {
		size_t csz = MIN(pmp->pr_size - n, pgc->pgc_chunksz);

		/*
		 * If we can't read out part of the victim's address
		 * space for some reason ignore that failure and try to
		 * emit a partial core file without that mapping's data.
		 * As in the kernel, we mark these failures with the
		 * PF_SUNW_FAILURE flag and store the errno where the
		 * mapping would have been.
		 */
		if (Pread(P, pgc->pgc_chunk, csz, pmp->pr_vaddr + n) != csz ||
		    gc_pwrite64(pgc->pgc_fd, pgc->pgc_chunk, csz,
		    *pgc->pgc_doff + n) != 0) {
			int err = errno;
			(void) gc_pwrite64(pgc->pgc_fd, &err, sizeof (err),
			    *pgc->pgc_doff);
			*pgc->pgc_doff += roundup(sizeof (err), 8);

			phdr.p_flags |= PF_SUNW_FAILURE;
			(void) ftruncate64(pgc->pgc_fd, *pgc->pgc_doff);
			goto exclude;
		}

		n += csz;
	}

	phdr.p_offset = *pgc->pgc_doff;
	phdr.p_filesz = pmp->pr_size;
	*pgc->pgc_doff += roundup(phdr.p_filesz, 8);

exclude:
	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		if (gc_pwrite64(pgc->pgc_fd, &phdr, sizeof (phdr),
		    *pgc->pgc_poff) != 0)
			return (1);

		*pgc->pgc_poff += sizeof (phdr);
#ifdef _LP64
	} else {
		Elf32_Phdr phdr32;

		bzero(&phdr32, sizeof (phdr32));
		phdr32.p_type = phdr.p_type;
		phdr32.p_vaddr = (Elf32_Addr)phdr.p_vaddr;
		phdr32.p_memsz = (Elf32_Word)phdr.p_memsz;
		phdr32.p_flags = phdr.p_flags;
		phdr32.p_offset = (Elf32_Off)phdr.p_offset;
		phdr32.p_filesz = (Elf32_Word)phdr.p_filesz;

		if (gc_pwrite64(pgc->pgc_fd, &phdr32, sizeof (phdr32),
		    *pgc->pgc_poff) != 0)
			return (1);

		*pgc->pgc_poff += sizeof (phdr32);
#endif	/* _LP64 */
	}

	return (0);
}

int
write_shstrtab(struct ps_prochandle *P, pgcore_t *pgc)
{
	off64_t off = *pgc->pgc_doff;
	size_t size = 0;
	shstrtab_t *s = &pgc->pgc_shstrtab;
	int i, ndx;

	if (shstrtab_size(s) == 1)
		return (0);

	/*
	 * Preemptively stick the name of the shstrtab in the string table.
	 */
	(void) shstrtab_ndx(&pgc->pgc_shstrtab, STR_SHSTRTAB);
	size = shstrtab_size(s);

	/*
	 * Dump all the strings that we used being sure we include the
	 * terminating null character.
	 */
	for (i = 0; i < STR_NUM; i++) {
		if ((ndx = s->sst_ndx[i]) != 0 || i == STR_NONE) {
			const char *str = shstrtab_data[i];
			size_t len = strlen(str) + 1;
			if (gc_pwrite64(pgc->pgc_fd, str, len, off + ndx) != 0)
				return (1);
		}
	}

	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		Elf32_Shdr shdr;

		bzero(&shdr, sizeof (shdr));
		shdr.sh_name = shstrtab_ndx(&pgc->pgc_shstrtab, STR_SHSTRTAB);
		shdr.sh_size = size;
		shdr.sh_offset = *pgc->pgc_doff;
		shdr.sh_addralign = 1;
		shdr.sh_flags = SHF_STRINGS;
		shdr.sh_type = SHT_STRTAB;

		if (gc_pwrite64(pgc->pgc_fd, &shdr, sizeof (shdr),
		    *pgc->pgc_soff) != 0)
			return (1);

		*pgc->pgc_soff += sizeof (shdr);
#ifdef _LP64
	} else {
		Elf64_Shdr shdr;

		bzero(&shdr, sizeof (shdr));
		shdr.sh_name = shstrtab_ndx(&pgc->pgc_shstrtab, STR_SHSTRTAB);
		shdr.sh_size = size;
		shdr.sh_offset = *pgc->pgc_doff;
		shdr.sh_addralign = 1;
		shdr.sh_flags = SHF_STRINGS;
		shdr.sh_type = SHT_STRTAB;

		if (gc_pwrite64(pgc->pgc_fd, &shdr, sizeof (shdr),
		    *pgc->pgc_soff) != 0)
			return (1);

		*pgc->pgc_soff += sizeof (shdr);
#endif	/* _LP64 */
	}

	*pgc->pgc_doff += roundup(size, 8);

	return (0);
}

/*
 * Don't explicity stop the process; that's up to the consumer.
 */
int
Pfgcore(struct ps_prochandle *P, int fd, core_content_t content)
{
	char plat[SYS_NMLN];
	char zonename[ZONENAME_MAX];
	int platlen = -1;
	pgcore_t pgc;
	off64_t poff, soff, doff, boff;
	struct utsname uts;
	uint_t nphdrs, nshdrs;

	if (ftruncate64(fd, 0) != 0)
		return (-1);

	if (content == CC_CONTENT_INVALID) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Cache the mappings and other useful data.
	 */
	(void) Prd_agent(P);
	(void) Ppsinfo(P);

	pgc.P = P;
	pgc.pgc_fd = fd;
	pgc.pgc_poff = &poff;
	pgc.pgc_soff = &soff;
	pgc.pgc_doff = &doff;
	pgc.pgc_content = content;
	pgc.pgc_chunksz = PAGESIZE;
	if ((pgc.pgc_chunk = malloc(pgc.pgc_chunksz)) == NULL)
		return (-1);

	shstrtab_init(&pgc.pgc_shstrtab);

	/*
	 * There are two PT_NOTE program headers for ancillary data, and
	 * one for each mapping.
	 */
	nphdrs = 2 + P->map_count;
	nshdrs = count_sections(&pgc);

	(void) Pplatform(P, plat, sizeof (plat));
	platlen = strlen(plat) + 1;
	Preadauxvec(P);
	(void) Puname(P, &uts);
	if (Pzonename(P, zonename, sizeof (zonename)) == NULL)
		zonename[0] = '\0';

	/*
	 * The core file contents may required zero section headers, but if we
	 * overflow the 16 bits allotted to the program header count in the ELF
	 * header, we'll need that program header at index zero.
	 */
	if (nshdrs == 0 && nphdrs >= PN_XNUM)
		nshdrs = 1;

	/*
	 * Set up the ELF header.
	 */
	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		Elf32_Ehdr ehdr;

		bzero(&ehdr, sizeof (ehdr));
		ehdr.e_ident[EI_MAG0] = ELFMAG0;
		ehdr.e_ident[EI_MAG1] = ELFMAG1;
		ehdr.e_ident[EI_MAG2] = ELFMAG2;
		ehdr.e_ident[EI_MAG3] = ELFMAG3;
		ehdr.e_type = ET_CORE;

		ehdr.e_ident[EI_CLASS] = ELFCLASS32;
#if defined(__sparc)
		ehdr.e_machine = EM_SPARC;
		ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#elif defined(__i386) || defined(__amd64)
		ehdr.e_machine = EM_386;
		ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
#error "unknown machine type"
#endif
		ehdr.e_ident[EI_VERSION] = EV_CURRENT;

		ehdr.e_version = EV_CURRENT;
		ehdr.e_ehsize = sizeof (ehdr);

		if (nphdrs >= PN_XNUM)
			ehdr.e_phnum = PN_XNUM;
		else
			ehdr.e_phnum = (unsigned short)nphdrs;

		ehdr.e_phentsize = sizeof (Elf32_Phdr);
		ehdr.e_phoff = ehdr.e_ehsize;

		if (nshdrs > 0) {
			if (nshdrs >= SHN_LORESERVE)
				ehdr.e_shnum = 0;
			else
				ehdr.e_shnum = (unsigned short)nshdrs;

			if (nshdrs - 1 >= SHN_LORESERVE)
				ehdr.e_shstrndx = SHN_XINDEX;
			else
				ehdr.e_shstrndx = (unsigned short)(nshdrs - 1);

			ehdr.e_shentsize = sizeof (Elf32_Shdr);
			ehdr.e_shoff = ehdr.e_phoff + ehdr.e_phentsize * nphdrs;
		}

		if (gc_pwrite64(fd, &ehdr, sizeof (ehdr), 0) != 0)
			goto err;

		poff = ehdr.e_phoff;
		soff = ehdr.e_shoff;
		doff = boff = ehdr.e_ehsize +
		    ehdr.e_phentsize * nphdrs +
		    ehdr.e_shentsize * nshdrs;

#ifdef _LP64
	} else {
		Elf64_Ehdr ehdr;

		bzero(&ehdr, sizeof (ehdr));
		ehdr.e_ident[EI_MAG0] = ELFMAG0;
		ehdr.e_ident[EI_MAG1] = ELFMAG1;
		ehdr.e_ident[EI_MAG2] = ELFMAG2;
		ehdr.e_ident[EI_MAG3] = ELFMAG3;
		ehdr.e_type = ET_CORE;

		ehdr.e_ident[EI_CLASS] = ELFCLASS64;
#if defined(__sparc)
		ehdr.e_machine = EM_SPARCV9;
		ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#elif defined(__i386) || defined(__amd64)
		ehdr.e_machine = EM_AMD64;
		ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
#error "unknown machine type"
#endif
		ehdr.e_ident[EI_VERSION] = EV_CURRENT;

		ehdr.e_version = EV_CURRENT;
		ehdr.e_ehsize = sizeof (ehdr);

		if (nphdrs >= PN_XNUM)
			ehdr.e_phnum = PN_XNUM;
		else
			ehdr.e_phnum = (unsigned short)nphdrs;

		ehdr.e_phentsize = sizeof (Elf64_Phdr);
		ehdr.e_phoff = ehdr.e_ehsize;

		if (nshdrs > 0) {
			if (nshdrs >= SHN_LORESERVE)
				ehdr.e_shnum = 0;
			else
				ehdr.e_shnum = (unsigned short)nshdrs;

			if (nshdrs - 1 >= SHN_LORESERVE)
				ehdr.e_shstrndx = SHN_XINDEX;
			else
				ehdr.e_shstrndx = (unsigned short)(nshdrs - 1);

			ehdr.e_shentsize = sizeof (Elf64_Shdr);
			ehdr.e_shoff = ehdr.e_phoff + ehdr.e_phentsize * nphdrs;
		}

		if (gc_pwrite64(fd, &ehdr, sizeof (ehdr), 0) != 0)
			goto err;

		poff = ehdr.e_phoff;
		soff = ehdr.e_shoff;
		doff = boff = ehdr.e_ehsize +
		    ehdr.e_phentsize * nphdrs +
		    ehdr.e_shentsize * nshdrs;

#endif	/* _LP64 */
	}

	/*
	 * Write the zero indexed section if it exists.
	 */
	if (nshdrs > 0 && write_shdr(&pgc, STR_NONE, 0, 0, 0, 0,
	    nshdrs >= SHN_LORESERVE ? nshdrs : 0,
	    nshdrs - 1 >= SHN_LORESERVE ? nshdrs - 1 : 0,
	    nphdrs >= PN_XNUM ? nphdrs : 0, 0, 0) != 0)
		goto err;

	/*
	 * Construct the old-style note header and section.
	 */

	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		prpsinfo_t prpsinfo;

		mkprpsinfo(P, &prpsinfo);
		if (write_note(fd, NT_PRPSINFO, &prpsinfo, sizeof (prpsinfo_t),
		    &doff) != 0) {
			goto err;
		}
		if (write_note(fd, NT_AUXV, P->auxv,
		    P->nauxv * sizeof (P->auxv[0]), &doff) != 0) {
			goto err;
		}
#ifdef _LP64
	} else {
		prpsinfo32_t pi32;
		auxv32_t *av32;
		size_t size = sizeof (auxv32_t) * P->nauxv;
		int i;

		mkprpsinfo32(P, &pi32);
		if (write_note(fd, NT_PRPSINFO, &pi32, sizeof (prpsinfo32_t),
		    &doff) != 0) {
			goto err;
		}

		if ((av32 = malloc(size)) == NULL)
			goto err;

		for (i = 0; i < P->nauxv; i++) {
			auxv_n_to_32(&P->auxv[i], &av32[i]);
		}

		if (write_note(fd, NT_AUXV, av32, size, &doff) != 0) {
			free(av32);
			goto err;
		}

		free(av32);
#endif	/* _LP64 */
	}

	if (write_note(fd, NT_PLATFORM, plat, platlen, &doff) != 0)
		goto err;

	if (Plwp_iter_all(P, old_per_lwp, &pgc) != 0)
		goto err;

	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		Elf32_Phdr phdr;

		bzero(&phdr, sizeof (phdr));
		phdr.p_type = PT_NOTE;
		phdr.p_flags = PF_R;
		phdr.p_offset = (Elf32_Off)boff;
		phdr.p_filesz = doff - boff;
		boff = doff;

		if (gc_pwrite64(fd, &phdr, sizeof (phdr), poff) != 0)
			goto err;
		poff += sizeof (phdr);
#ifdef _LP64
	} else {
		Elf64_Phdr phdr;

		bzero(&phdr, sizeof (phdr));
		phdr.p_type = PT_NOTE;
		phdr.p_flags = PF_R;
		phdr.p_offset = boff;
		phdr.p_filesz = doff - boff;
		boff = doff;

		if (gc_pwrite64(fd, &phdr, sizeof (phdr), poff) != 0)
			goto err;
		poff += sizeof (phdr);
#endif	/* _LP64 */
	}

	/*
	 * Construct the new-style note header and section.
	 */

	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		if (write_note(fd, NT_PSINFO, &P->psinfo, sizeof (psinfo_t),
		    &doff) != 0) {
			goto err;
		}
		if (write_note(fd, NT_PSTATUS, &P->status, sizeof (pstatus_t),
		    &doff) != 0) {
			goto err;
		}
		if (write_note(fd, NT_AUXV, P->auxv,
		    P->nauxv * sizeof (P->auxv[0]), &doff) != 0) {
			goto err;
		}
#ifdef _LP64
	} else {
		psinfo32_t pi32;
		pstatus32_t ps32;
		auxv32_t *av32;
		size_t size = sizeof (auxv32_t) * P->nauxv;
		int i;

		psinfo_n_to_32(&P->psinfo, &pi32);
		if (write_note(fd, NT_PSINFO, &pi32, sizeof (psinfo32_t),
		    &doff) != 0) {
			goto err;
		}
		pstatus_n_to_32(&P->status, &ps32);
		if (write_note(fd, NT_PSTATUS, &ps32, sizeof (pstatus32_t),
		    &doff) != 0) {
			goto err;
		}
		if ((av32 = malloc(size)) == NULL)
			goto err;

		for (i = 0; i < P->nauxv; i++) {
			auxv_n_to_32(&P->auxv[i], &av32[i]);
		}

		if (write_note(fd, NT_AUXV, av32, size, &doff) != 0) {
			free(av32);
			goto err;
		}

		free(av32);
#endif	/* _LP64 */
	}

	if (write_note(fd, NT_PLATFORM, plat, platlen, &doff) != 0 ||
	    write_note(fd, NT_UTSNAME, &uts, sizeof (uts), &doff) != 0 ||
	    write_note(fd, NT_CONTENT, &content, sizeof (content), &doff) != 0)
		goto err;

	{
		prcred_t cred, *cp;
		size_t size = sizeof (prcred_t);

		if (Pcred(P, &cred, 0) != 0)
			goto err;

		if (cred.pr_ngroups > 0)
			size += sizeof (gid_t) * (cred.pr_ngroups - 1);
		if ((cp = malloc(size)) == NULL)
			goto err;

		if (Pcred(P, cp, cred.pr_ngroups) != 0 ||
		    write_note(fd, NT_PRCRED, cp, size, &doff) != 0) {
			free(cp);
			goto err;
		}

		free(cp);
	}

	{
		prpriv_t *ppriv = NULL;
		const priv_impl_info_t *pinfo;
		size_t pprivsz, pinfosz;

		if (Ppriv(P, &ppriv) == -1)
			goto err;
		pprivsz = PRIV_PRPRIV_SIZE(ppriv);

		if (write_note(fd, NT_PRPRIV, ppriv, pprivsz, &doff) != 0) {
			Ppriv_free(P, ppriv);
			goto err;
		}
		Ppriv_free(P, ppriv);

		if ((pinfo = getprivimplinfo()) == NULL)
			goto err;
		pinfosz = PRIV_IMPL_INFO_SIZE(pinfo);

		if (write_note(fd, NT_PRPRIVINFO, pinfo, pinfosz, &doff) != 0)
			goto err;
	}

	if (write_note(fd, NT_ZONENAME, zonename, strlen(zonename) + 1,
	    &doff) != 0)
		goto err;

	{
		fditer_t iter;
		iter.fd_fd = fd;
		iter.fd_doff = &doff;

		if (Pfdinfo_iter(P, iter_fd, &iter) != 0)
			goto err;
	}

#if defined(__i386) || defined(__amd64)
	/* CSTYLED */
	{
		struct ssd *ldtp;
		size_t size;
		int nldt;

		/*
		 * Only dump out non-zero sized LDT notes.
		 */
		if ((nldt = Pldt(P, NULL, 0)) != 0) {
			size = sizeof (struct ssd) * nldt;
			if ((ldtp = malloc(size)) == NULL)
				goto err;

			if (Pldt(P, ldtp, nldt) == -1 ||
			    write_note(fd, NT_LDT, ldtp, size, &doff) != 0) {
				free(ldtp);
				goto err;
			}

			free(ldtp);
		}
	}
#endif	/* __i386 || __amd64 */

	if (Plwp_iter_all(P, new_per_lwp, &pgc) != 0)
		goto err;

	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		Elf32_Phdr phdr;

		bzero(&phdr, sizeof (phdr));
		phdr.p_type = PT_NOTE;
		phdr.p_flags = PF_R;
		phdr.p_offset = (Elf32_Off)boff;
		phdr.p_filesz = doff - boff;
		boff = doff;

		if (gc_pwrite64(fd, &phdr, sizeof (phdr), poff) != 0)
			goto err;
		poff += sizeof (phdr);
#ifdef _LP64
	} else {
		Elf64_Phdr phdr;

		bzero(&phdr, sizeof (phdr));
		phdr.p_type = PT_NOTE;
		phdr.p_flags = PF_R;
		phdr.p_offset = boff;
		phdr.p_filesz = doff - boff;
		boff = doff;

		if (gc_pwrite64(fd, &phdr, sizeof (phdr), poff) != 0)
			goto err;
		poff += sizeof (phdr);
#endif	/* _LP64 */
	}

	/*
	 * Construct the headers for each mapping and write out its data
	 * if the content parameter indicates that it should be present
	 * in the core file.
	 */
	if (Pmapping_iter(P, dump_map, &pgc) != 0)
		goto err;

	if (dump_sections(&pgc) != 0)
		goto err;

	if (write_shstrtab(P, &pgc) != 0)
		goto err;

	free(pgc.pgc_chunk);

	return (0);

err:
	/*
	 * Wipe out anything we may have written if there was an error.
	 */
	(void) ftruncate64(fd, 0);
	free(pgc.pgc_chunk);
	return (-1);
}

static const char *content_str[] = {
	"stack",	/* CC_CONTENT_STACK */
	"heap",		/* CC_CONTENT_HEAP */
	"shfile",	/* CC_CONTENT_SHFILE */
	"shanon",	/* CC_CONTENT_SHANON */
	"text",		/* CC_CONTENT_TEXT */
	"data",		/* CC_CONTENT_DATA */
	"rodata",	/* CC_CONTENT_RODATA */
	"anon",		/* CC_CONTENT_ANON */
	"shm",		/* CC_CONTENT_SHM */
	"ism",		/* CC_CONTENT_ISM */
	"dism",		/* CC_CONTENT_DISM */
	"ctf",		/* CC_CONTENT_CTF */
	"symtab",	/* CC_CONTENT_SYMTAB */
};

static uint_t ncontent_str = sizeof (content_str) / sizeof (content_str[0]);

#define	STREQ(a, b, n)	(strlen(b) == (n) && strncmp(a, b, n) == 0)

int
proc_str2content(const char *str, core_content_t *cp)
{
	const char *cur = str;
	int add = 1;
	core_content_t mask, content = 0;

	for (;;) {
		for (cur = str; isalpha(*cur); cur++)
			continue;

		if (STREQ(str, "default", cur - str)) {
			mask = CC_CONTENT_DEFAULT;
		} else if (STREQ(str, "all", cur - str)) {
			mask = CC_CONTENT_ALL;
		} else if (STREQ(str, "none", cur - str)) {
			mask = 0;
		} else {
			int i = 0;

			while (!STREQ(str, content_str[i], cur - str)) {
				i++;

				if (i >= ncontent_str)
					return (-1);
			}

			mask = (core_content_t)1 << i;
		}

		if (add)
			content |= mask;
		else
			content &= ~mask;

		switch (*cur) {
		case '\0':
			*cp = content;
			return (0);
		case '+':
			add = 1;
			break;
		case '-':
			add = 0;
			break;
		default:
			return (-1);
		}

		str = cur + 1;
	}
}

static int
popc(core_content_t x)
{
	int i;

	for (i = 0; x != 0; i++)
		x &= x - 1;

	return (i);
}

int
proc_content2str(core_content_t content, char *buf, size_t size)
{
	int nonecnt, defcnt, allcnt;
	core_content_t mask, bit;
	int first;
	uint_t index;
	size_t n, tot = 0;

	if (content == 0)
		return ((int)strlcpy(buf, "none", size));

	if (content & ~CC_CONTENT_ALL)
		return ((int)strlcpy(buf, "<invalid>", size));

	nonecnt = popc(content);
	defcnt = 1 + popc(content ^ CC_CONTENT_DEFAULT);
	allcnt = 1 + popc(content ^ CC_CONTENT_ALL);

	if (defcnt <= nonecnt && defcnt <= allcnt) {
		mask = content ^ CC_CONTENT_DEFAULT;
		first = 0;
		tot += (n = strlcpy(buf, "default", size));
		if (n > size)
			n = size;
		buf += n;
		size -= n;
	} else if (allcnt < nonecnt) {
		mask = content ^ CC_CONTENT_ALL;
		first = 0;
		tot += (n = strlcpy(buf, "all", size));
		if (n > size)
			n = size;
		buf += n;
		size -= n;
	} else {
		mask = content;
		first = 1;
	}

	while (mask != 0) {
		bit = mask ^ (mask & (mask - 1));

		if (!first) {
			if (size > 1) {
				*buf = (bit & content) ? '+' : '-';
				buf++;
				size--;
			}

			tot++;
		}
		index = popc(bit - 1);
		tot += (n = strlcpy(buf, content_str[index], size));
		if (n > size)
			n = size;
		buf += n;
		size -= n;

		mask ^= bit;
		first = 0;
	}

	return ((int)tot);
}
