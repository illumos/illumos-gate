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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <stdarg.h>
#include <string.h>
#include "Pcontrol.h"

/*
 * This file implements the process services declared in <proc_service.h>.
 * This enables libproc to be used in conjunction with libc_db and
 * librtld_db.  As most of these facilities are already provided by
 * (more elegant) interfaces in <libproc.h>, we can just call those.
 *
 * NOTE: We explicitly do *not* implement the functions ps_kill() and
 * ps_lrolltoaddr() in this library.  The very existence of these functions
 * causes libc_db to create an "agent thread" in the target process.
 * The only way to turn off this behavior is to omit these functions.
 */

#pragma weak ps_pdread = ps_pread
#pragma weak ps_ptread = ps_pread
#pragma weak ps_pdwrite = ps_pwrite
#pragma weak ps_ptwrite = ps_pwrite

ps_err_e
ps_pdmodel(struct ps_prochandle *P, int *modelp)
{
	*modelp = P->status.pr_dmodel;
	return (PS_OK);
}

ps_err_e
ps_pread(struct ps_prochandle *P, psaddr_t addr, void *buf, size_t size)
{
	if (P->ops.pop_pread(P, buf, size, addr, P->data) != size)
		return (PS_BADADDR);
	return (PS_OK);
}

ps_err_e
ps_pwrite(struct ps_prochandle *P, psaddr_t addr, const void *buf, size_t size)
{
	if (P->ops.pop_pwrite(P, buf, size, addr, P->data) != size)
		return (PS_BADADDR);
	return (PS_OK);
}

/*
 * libc_db calls matched pairs of ps_pstop()/ps_pcontinue()
 * in the belief that the client may have left the process
 * running while calling in to the libc_db interfaces.
 *
 * We interpret the meaning of these functions to be an inquiry
 * as to whether the process is stopped, not an action to be
 * performed to make it stopped.  For similar reasons, we also
 * return PS_OK for core files in order to allow libc_db to
 * operate on these as well.
 */
ps_err_e
ps_pstop(struct ps_prochandle *P)
{
	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);
	return (PS_OK);
}

ps_err_e
ps_pcontinue(struct ps_prochandle *P)
{
	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);
	return (PS_OK);
}

/*
 * ps_lstop() and ps_lcontinue() are not called by any code in libc_db
 * or librtld_db.  We make them behave like ps_pstop() and ps_pcontinue().
 */
/* ARGSUSED1 */
ps_err_e
ps_lstop(struct ps_prochandle *P, lwpid_t lwpid)
{
	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);
	return (PS_OK);
}

/* ARGSUSED1 */
ps_err_e
ps_lcontinue(struct ps_prochandle *P, lwpid_t lwpid)
{
	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);
	return (PS_OK);
}

ps_err_e
ps_lgetregs(struct ps_prochandle *P, lwpid_t lwpid, prgregset_t regs)
{
	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);

	if (Plwp_getregs(P, lwpid, regs) == 0)
		return (PS_OK);

	return (PS_BADLID);
}

ps_err_e
ps_lsetregs(struct ps_prochandle *P, lwpid_t lwpid, const prgregset_t regs)
{
	if (P->state != PS_STOP)
		return (PS_ERR);

	if (Plwp_setregs(P, lwpid, regs) == 0)
		return (PS_OK);

	return (PS_BADLID);
}

ps_err_e
ps_lgetfpregs(struct ps_prochandle *P, lwpid_t lwpid, prfpregset_t *regs)
{
	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);

	if (Plwp_getfpregs(P, lwpid, regs) == 0)
		return (PS_OK);

	return (PS_BADLID);
}

ps_err_e
ps_lsetfpregs(struct ps_prochandle *P, lwpid_t lwpid, const prfpregset_t *regs)
{
	if (P->state != PS_STOP)
		return (PS_ERR);

	if (Plwp_setfpregs(P, lwpid, regs) == 0)
		return (PS_OK);

	return (PS_BADLID);
}

#if defined(sparc) || defined(__sparc)

ps_err_e
ps_lgetxregsize(struct ps_prochandle *P, lwpid_t lwpid, int *xrsize)
{
	char fname[PATH_MAX];
	struct stat statb;

	if (P->state == PS_DEAD) {
		core_info_t *core = P->data;
		lwp_info_t *lwp = list_next(&core->core_lwp_head);
		uint_t i;

		for (i = 0; i < core->core_nlwp; i++, lwp = list_next(lwp)) {
			if (lwp->lwp_id == lwpid) {
				if (lwp->lwp_xregs != NULL)
					*xrsize = sizeof (prxregset_t);
				else
					*xrsize = 0;
				return (PS_OK);
			}
		}

		return (PS_BADLID);
	}

	(void) snprintf(fname, sizeof (fname), "%s/%d/lwp/%d/xregs",
	    procfs_path, (int)P->status.pr_pid, (int)lwpid);

	if (stat(fname, &statb) != 0)
		return (PS_BADLID);

	*xrsize = (int)statb.st_size;
	return (PS_OK);
}

ps_err_e
ps_lgetxregs(struct ps_prochandle *P, lwpid_t lwpid, caddr_t xregs)
{
	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);

	/* LINTED - alignment */
	if (Plwp_getxregs(P, lwpid, (prxregset_t *)xregs) == 0)
		return (PS_OK);

	return (PS_BADLID);
}

ps_err_e
ps_lsetxregs(struct ps_prochandle *P, lwpid_t lwpid, caddr_t xregs)
{
	if (P->state != PS_STOP)
		return (PS_ERR);

	/* LINTED - alignment */
	if (Plwp_setxregs(P, lwpid, (prxregset_t *)xregs) == 0)
		return (PS_OK);

	return (PS_BADLID);
}

#endif	/* sparc */

#if defined(__i386) || defined(__amd64)

ps_err_e
ps_lgetLDT(struct ps_prochandle *P, lwpid_t lwpid, struct ssd *ldt)
{
#if defined(__amd64) && defined(_LP64)
	if (P->status.pr_dmodel != PR_MODEL_NATIVE) {
#endif
	prgregset_t regs;
	struct ssd *ldtarray;
	ps_err_e error;
	uint_t gs;
	int nldt;
	int i;

	if (P->state != PS_STOP && P->state != PS_DEAD)
		return (PS_ERR);

	/*
	 * We need to get the ldt entry that matches the
	 * value in the lwp's GS register.
	 */
	if ((error = ps_lgetregs(P, lwpid, regs)) != PS_OK)
		return (error);

	gs = regs[GS];

	if ((nldt = Pldt(P, NULL, 0)) <= 0 ||
	    (ldtarray = malloc(nldt * sizeof (struct ssd))) == NULL)
		return (PS_ERR);
	if ((nldt = Pldt(P, ldtarray, nldt)) <= 0) {
		free(ldtarray);
		return (PS_ERR);
	}

	for (i = 0; i < nldt; i++) {
		if (gs == ldtarray[i].sel) {
			*ldt = ldtarray[i];
			break;
		}
	}
	free(ldtarray);

	if (i < nldt)
		return (PS_OK);
#if defined(__amd64) && defined(_LP64)
	}
#endif

	return (PS_ERR);
}

#endif	/* __i386 || __amd64 */

/*
 * Libthread_db doesn't use this function currently, but librtld_db uses
 * it for its debugging output.  We turn this on via rd_log if our debugging
 * switch is on, and then echo the messages sent to ps_plog to stderr.
 */
void
ps_plog(const char *fmt, ...)
{
	va_list ap;

	if (_libproc_debug && fmt != NULL && *fmt != '\0') {
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
		if (fmt[strlen(fmt) - 1] != '\n')
			(void) fputc('\n', stderr);
	}
}

/*
 * Store a pointer to our internal copy of the aux vector at the address
 * specified by the caller.  It should not hold on to this data for too long.
 */
ps_err_e
ps_pauxv(struct ps_prochandle *P, const auxv_t **aux)
{
	if (P->auxv == NULL)
		Preadauxvec(P);

	if (P->auxv == NULL)
		return (PS_ERR);

	*aux = (const auxv_t *)P->auxv;
	return (PS_OK);
}

ps_err_e
ps_pbrandname(struct ps_prochandle *P, char *buf, size_t len)
{
	return (Pbrandname(P, buf, len) ? PS_OK : PS_ERR);
}

/*
 * Search for a symbol by name and return the corresponding address.
 */
ps_err_e
ps_pglobal_lookup(struct ps_prochandle *P, const char *object_name,
	const char *sym_name, psaddr_t *sym_addr)
{
	GElf_Sym sym;

	if (Plookup_by_name(P, object_name, sym_name, &sym) == 0) {
		dprintf("pglobal_lookup <%s> -> %p\n",
		    sym_name, (void *)(uintptr_t)sym.st_value);
		*sym_addr = (psaddr_t)sym.st_value;
		return (PS_OK);
	}

	return (PS_NOSYM);
}

/*
 * Search for a symbol by name and return the corresponding symbol
 * information.  If we're compiled _LP64, we just call Plookup_by_name
 * and return because ps_sym_t is defined to be an Elf64_Sym, which
 * is the same as a GElf_Sym.  In the _ILP32 case, we have to convert
 * Plookup_by_name's result back to a ps_sym_t (which is an Elf32_Sym).
 */
ps_err_e
ps_pglobal_sym(struct ps_prochandle *P, const char *object_name,
	const char *sym_name, ps_sym_t *symp)
{
#if defined(_ILP32)
	GElf_Sym sym;

	if (Plookup_by_name(P, object_name, sym_name, &sym) == 0) {
		symp->st_name = (Elf32_Word)sym.st_name;
		symp->st_value = (Elf32_Addr)sym.st_value;
		symp->st_size = (Elf32_Word)sym.st_size;
		symp->st_info = ELF32_ST_INFO(
		    GELF_ST_BIND(sym.st_info), GELF_ST_TYPE(sym.st_info));
		symp->st_other = sym.st_other;
		symp->st_shndx = sym.st_shndx;
		return (PS_OK);
	}

#elif defined(_LP64)
	if (Plookup_by_name(P, object_name, sym_name, symp) == 0)
		return (PS_OK);
#endif
	return (PS_NOSYM);
}
