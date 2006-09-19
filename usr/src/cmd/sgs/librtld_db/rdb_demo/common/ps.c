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
#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <procfs.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <libelf.h>
#include <sys/param.h>
#include <stdarg.h>

#include <proc_service.h>

#include "rdb.h"
#include "disasm.h"


#if	!defined(_LP64)
static void
gelf_sym_to_elf32(GElf_Sym *src, Elf32_Sym *dst)
{
	dst->st_name	= src->st_name;
	/* LINTED */
	dst->st_value	= (Elf32_Addr)src->st_value;
	/* LINTED */
	dst->st_size	= (Elf32_Word)src->st_size;
	dst->st_info	= ELF32_ST_INFO(GELF_ST_BIND(src->st_info),
				GELF_ST_TYPE(src->st_info));
	dst->st_other	= src->st_other;
	dst->st_shndx	= src->st_shndx;
}
#endif

static void
get_ldbase(struct ps_prochandle *procp)
{
	int		pauxvfd;
	char		pname[MAXPATHLEN];
	struct stat	stbuf;
	void		*auxvptr, *auxvtail;
	auxv_t		*auxvp;
	uint_t		entsize;

	(void) snprintf(pname, MAXPATHLEN, "/proc/%d/auxv", procp->pp_pid);
	if ((pauxvfd = open(pname, O_RDONLY)) == -1)
		perr("open auxv");

	if (fstat(pauxvfd, &stbuf) == -1)
		perr("stat auxv");

	auxvptr = malloc(stbuf.st_size);
	if (read(pauxvfd, auxvptr, stbuf.st_size) == -1)
		perr("gldb: reading auxv");

	close(pauxvfd);

	procp->pp_auxvp = auxvptr;
	auxvtail = (void *)((uintptr_t)auxvptr + stbuf.st_size);

#if defined(_LP64)
	if (procp->pp_dmodel == PR_MODEL_ILP32)
		entsize = sizeof (auxv32_t);
	else
#endif
		entsize = sizeof (auxv_t);

	while (auxvptr < auxvtail) {
		auxvp = auxvptr;
		if (auxvp->a_type == AT_BASE) {
#if defined(_LP64)
			if (procp->pp_dmodel == PR_MODEL_ILP32)
				procp->pp_ldsobase =
				    ((uintptr_t)((auxv32_t *)auxvp)->
				    a_un.a_val);
			else
#endif
				procp->pp_ldsobase =  auxvp->a_un.a_val;
		} else if (auxvp->a_type == AT_PHDR) {
#if defined(_LP64)
			if (procp->pp_dmodel == PR_MODEL_ILP32)
				procp->pp_execphdr =
				    ((uintptr_t)((auxv32_t *)auxvp)->
				    a_un.a_val);
			else
#endif
				procp->pp_execphdr =  auxvp->a_un.a_val;
		}
		auxvptr = (void *)((uintptr_t)auxvptr + entsize);
	}
}

retc_t
ps_init(int pctlfd, int pstatusfd, pid_t pid, struct ps_prochandle *procp)
{
	rd_notify_t	rd_notify;
	char		procname[MAXPATHLEN];
	long		oper;
	long		pflags;
	struct iovec	piov[2];

	procp->pp_pid = pid;
	procp->pp_ctlfd = pctlfd;
	procp->pp_statusfd = pstatusfd;

	(void) sprintf(procname, "/proc/%d/map", procp->pp_pid);
	if ((procp->pp_mapfd = open(procname, O_RDONLY)) == -1)
		perr("psi: open of /proc/dpid/map failed");

	(void) sprintf(procname, "/proc/%d/as", procp->pp_pid);
	if ((procp->pp_asfd = open(procname, O_RDWR)) == -1)
		perr("psi: open of /proc/dpid/as failed");

	if (ps_pdmodel(procp, &procp->pp_dmodel) != PS_OK)
		perr("psi: data model");

#if	!defined(_LP64)
	if (procp->pp_dmodel == PR_MODEL_LP64)
		perr("psi:  run 64-bit rdb to debug a 64-bit process");
#endif

	get_ldbase(procp);

	load_map(procp, (caddr_t)procp->pp_ldsobase, &(procp->pp_ldsomap));
	procp->pp_ldsomap.mi_addr += procp->pp_ldsobase;
	procp->pp_ldsomap.mi_end += procp->pp_ldsobase;
	procp->pp_ldsomap.mi_name = "<procfs: interp>";

	load_map(procp, (caddr_t)procp->pp_execphdr, &(procp->pp_execmap));
	procp->pp_execmap.mi_name = "<procfs: exec>";

	procp->pp_breakpoints = 0;
	procp->pp_flags = FLG_PP_PACT | FLG_PP_PLTSKIP;
	procp->pp_lmaplist.ml_head = 0;
	procp->pp_lmaplist.ml_tail = 0;
	if ((procp->pp_rap = rd_new(procp)) == 0) {
		fprintf(stderr, "rdb: rtld_db: rd_new() call failed\n");
		exit(1);
	}
	rd_event_enable(procp->pp_rap, 1);

	/*
	 * For those architectures that increment the PC on
	 * a breakpoint fault we enable the PR_BPTADJ adjustments.
	 */
	oper = PCSET;
	pflags = PR_BPTADJ;
	piov[0].iov_base = (caddr_t)(&oper);
	piov[0].iov_len = sizeof (oper);
	piov[1].iov_base = (caddr_t)(&pflags);
	piov[1].iov_len = sizeof (pflags);
	if (writev(procp->pp_ctlfd, piov, 2) == -1)
		perr("psinit: PCSET(PR_BTPADJ)");


	/*
	 * Set breakpoints for special handshakes between librtld_db.so
	 * and the debugger.  These include:
	 *	PREINIT		- before .init processing.
	 *	POSTINIT	- after .init processing
	 *	DLACTIVITY	- link_maps status has changed
	 */
	if (rd_event_addr(procp->pp_rap, RD_PREINIT, &rd_notify) == RD_OK) {
		if (set_breakpoint(procp, rd_notify.u.bptaddr,
		    FLG_BP_RDPREINIT) != RET_OK)
			fprintf(stderr,
				"psi: failed to set BP for preinit at: 0x%lx\n",
				rd_notify.u.bptaddr);
	} else
		fprintf(stderr, "psi: no event registered for preinit\n");

	if (rd_event_addr(procp->pp_rap, RD_POSTINIT, &rd_notify) == RD_OK) {
		if (set_breakpoint(procp, rd_notify.u.bptaddr,
		    FLG_BP_RDPOSTINIT) != RET_OK)
			fprintf(stderr,
			    "psi: failed to set BP for postinit at: 0x%lx\n",
			    rd_notify.u.bptaddr);
	} else
		fprintf(stderr, "psi: no event registered for postinit\n");

	if (rd_event_addr(procp->pp_rap, RD_DLACTIVITY, &rd_notify) == RD_OK) {
		if (set_breakpoint(procp, rd_notify.u.bptaddr,
		    FLG_BP_RDDLACT) != RET_OK)
			fprintf(stderr,
				"psi: failed to set BP for dlact at: 0x%lx\n",
				rd_notify.u.bptaddr);
	} else
		fprintf(stderr, "psi: no event registered for dlact\n");

	return (RET_OK);
}


retc_t
ps_close(struct ps_prochandle *ph)
{
	delete_all_breakpoints(ph);
	if (ph->pp_auxvp)
		free(ph->pp_auxvp);
	free_linkmaps(ph);
	return (RET_OK);
}


ps_err_e
ps_pauxv(struct ps_prochandle *ph, const auxv_t **auxvp)
{
	*auxvp = ph->pp_auxvp;
	return (PS_OK);
}


ps_err_e
ps_pdmodel(struct ps_prochandle *ph, int *dm)
{
	pstatus_t	pstatus;

	if (pread(ph->pp_statusfd, &pstatus, sizeof (pstatus), 0) == -1)
		return (PS_ERR);

	*dm = (int)pstatus.pr_dmodel;
	return (PS_OK);
}


ps_err_e
ps_pread(struct ps_prochandle *ph, psaddr_t addr, void *buf, size_t size)
{
	/* LINTED */
	if (pread(ph->pp_asfd, buf, size, (off_t)addr) != size)
		return (PS_ERR);

	return (PS_OK);
}


ps_err_e
ps_pwrite(struct ps_prochandle *ph, psaddr_t addr, const void *buf, size_t size)
{
	/* LINTED */
	if (pwrite(ph->pp_asfd, buf, size, (off_t)addr) != size)
		return (PS_ERR);

	return (PS_OK);
}


ps_err_e
ps_pglobal_sym(struct ps_prochandle *ph, const char *object_name,
    const char *sym_name, ps_sym_t *symp)
{
	map_info_t	*mip;
	GElf_Sym	gsym;

	if ((mip = str_to_map(ph, object_name)) == 0)
		return (PS_ERR);

	if (str_map_sym(sym_name, mip, &gsym, NULL) == RET_FAILED)
		return (PS_ERR);

#if	defined(_LP64)
	*symp = gsym;
#else
	gelf_sym_to_elf32(&gsym, (Elf32_Sym *)symp);
#endif

	return (PS_OK);
}


ps_err_e
ps_pglobal_lookup(struct ps_prochandle *ph, const char *object_name,
    const char *sym_name, ulong_t *sym_addr)
{
	GElf_Sym	sym;
	map_info_t	*mip;

	if ((mip = str_to_map(ph, object_name)) == 0)
		return (PS_ERR);

	if (str_map_sym(sym_name, mip, &sym, NULL) == RET_FAILED)
		return (PS_ERR);

	*sym_addr = sym.st_value;

	return (PS_OK);
}


ps_err_e
ps_lgetregs(struct ps_prochandle *ph, lwpid_t lid, prgregset_t gregset)
{
	char		procname[MAXPATHLEN];
	int		lwpfd;
	lwpstatus_t	lwpstatus;

	(void) snprintf(procname, MAXPATHLEN - 1,
		"/proc/%d/lwp/%d/lwpstatus", ph->pp_pid, lid);

	if ((lwpfd = open(procname, O_RDONLY)) == -1)
		return (PS_ERR);

	if (read(lwpfd, &lwpstatus, sizeof (lwpstatus)) == -1)
		return (PS_ERR);

	gregset = lwpstatus.pr_reg;

	close(lwpfd);
	return (PS_OK);
}


void
ps_plog(const char *fmt, ...)
{
	va_list		args;
	static FILE	*log_fp = 0;

	if (log_fp == 0) {
		char		log_fname[256];
		(void) sprintf(log_fname, "/tmp/tdlog.%d", getpid());
		if ((log_fp = fopen(log_fname, "w")) == 0) {
			/*
			 * unable to open log file - default to
			 * stderr.
			 */
			fprintf(stderr, "unable to open %s, logging "
				"redirected to stderr", log_fname);
			log_fp = stderr;
		}
	}

	va_start(args, fmt);
	vfprintf(log_fp, fmt, args);
	va_end(args);
	fputc('\n', log_fp);
	fflush(log_fp);
}

ps_err_e
ps_pbrandname(struct ps_prochandle *P, char *buf, size_t len)
{
	return (PS_ERR);
}
