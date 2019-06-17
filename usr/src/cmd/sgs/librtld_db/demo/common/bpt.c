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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <libelf.h>
#include <sys/param.h>
#include <sys/machelf.h>
#include <stdarg.h>

#include "rdb.h"

static const char *fault_strings[] = {
	"<null string>",
	"illegal instruction",
	"privileged instruction",
	"breakpoint instruction",
	"trace trap (single-step)",
	"Memory access (e.g., alignment)",
	"Memory bounds (invalid address)",
	"Integer overflow",
	"Integer zero divide"
	"Floating-point exception",
	"Irrecoverable stack faul",
	"Recoverable page fault (no associated sig)"
};

#define	MAXFAULT	FLTPAGE

retc_t
set_breakpoint(struct ps_prochandle *ph, ulong_t addr, unsigned flags)
{
	bptlist_t	*new, *cur, *prev;

	for (cur = ph->pp_breakpoints, prev = NULL;
	    (cur && (cur->bl_addr < addr));
	    prev = cur, cur = cur->bl_next)
		;
	if (cur && (cur->bl_addr == addr)) {
		/*
		 * already have break point set here.
		 */
		cur->bl_flags |= flags;
		return (RET_OK);
	}

	new = malloc(sizeof (bptlist_t));
	new->bl_addr = addr;
	new->bl_flags = flags;
	if (prev == NULL) {
		/*
		 * insert at head
		 */
		new->bl_next = ph->pp_breakpoints;
		ph->pp_breakpoints = new;
		return (RET_OK);
	}

	prev->bl_next = new;
	new->bl_next = cur;
	return (RET_OK);
}

static bptlist_t *
find_bp(struct ps_prochandle *ph, ulong_t addr)
{
	bptlist_t	*cur;

	for (cur = ph->pp_breakpoints;
	    (cur && (cur->bl_addr != addr));
	    cur = cur->bl_next)
		;

	if ((cur == NULL) || (cur->bl_addr != addr))
		return ((bptlist_t *)-1);
	return (cur);
}

static retc_t
delete_bp(struct ps_prochandle *ph, ulong_t addr)
{
	bptlist_t	*cur, *prev;

	for (cur = ph->pp_breakpoints, prev = NULL;
	    (cur && (cur->bl_addr < addr));
	    prev = cur, cur = cur->bl_next)
		;
	if ((cur == NULL) || (cur->bl_addr != addr))
		return (RET_FAILED);

	if (prev == NULL)
		ph->pp_breakpoints = cur->bl_next;
	else
		prev->bl_next = cur->bl_next;

	free(cur);
	return (RET_OK);
}

void
list_breakpoints(struct ps_prochandle *ph)
{
	bptlist_t	*cur;

	if (ph->pp_breakpoints == NULL) {
		(void) printf("no active breakpoints.\n");
		return;
	}

	(void) printf("active breakpoints:\n");
	for (cur = ph->pp_breakpoints; cur; cur = cur->bl_next) {
		(void) printf("\t0x%08lx:0x%04x - %s\n", cur->bl_addr,
		    cur->bl_flags, print_address_ps(ph, cur->bl_addr,
		    FLG_PAP_SONAME));
	}
}

static void
set_breaks(struct ps_prochandle *ph)
{
	bptlist_t	*cur;
	bptinstr_t	bpt_instr = BPINSTR;

	for (cur = ph->pp_breakpoints; cur; cur = cur->bl_next) {
		bptinstr_t	old_inst = 0;

		if (ps_pread(ph, cur->bl_addr, (char *)&old_inst,
		    sizeof (bptinstr_t)) != PS_OK)
			perr("sb: error setting breakpoint");

		cur->bl_instr = old_inst;

		if (ps_pwrite(ph, cur->bl_addr, (char *)&bpt_instr,
		    sizeof (bptinstr_t)) != PS_OK)
			perr("sb1: error setting breakpoint\n");
	}

}

static void
clear_breaks(struct ps_prochandle *ph)
{
	bptlist_t	*cur;

	/*
	 * Restore all the original instructions
	 */
	for (cur = ph->pp_breakpoints; cur; cur = cur->bl_next)
		if (ps_pwrite(ph, cur->bl_addr, (char *)&(cur->bl_instr),
		    sizeof (bptinstr_t)) != PS_OK)
			perr("cb: error clearing breakpoint");
}

retc_t
delete_all_breakpoints(struct ps_prochandle *ph)
{
	bptlist_t	*cur, *prev;

	if (ph->pp_breakpoints == NULL)
		return (RET_OK);

	for (prev = NULL, cur = ph->pp_breakpoints;
	    cur; prev = cur, cur = cur->bl_next)
		if (prev)
			free(prev);
	if (prev)
		free(prev);

	ph->pp_breakpoints = NULL;
	return (RET_OK);
}

retc_t
delete_breakpoint(struct ps_prochandle *ph, ulong_t addr, unsigned flags)
{
	bptlist_t	*bpt;

	if (((bpt = find_bp(ph, addr)) == (bptlist_t *)-1) ||
	    ((bpt->bl_flags & flags) == 0))
		return (RET_FAILED);

	bpt->bl_flags &= ~flags;
	if (bpt->bl_flags)
		return (RET_OK);

	return (delete_bp(ph, addr));
}

static void
handle_sp_break(struct ps_prochandle *ph)
{
	rd_event_msg_t	emt;

	if (rd_event_getmsg(ph->pp_rap, &emt) != RD_OK) {
		(void) fprintf(stderr, "hsb: failed rd_event_getmsg()\n");
		return;
	}

	if (emt.type == RD_DLACTIVITY) {
		if (emt.u.state == RD_CONSISTENT)
			ph->pp_flags |= FLG_PP_LMAPS;
		else
			ph->pp_flags &= ~FLG_PP_LMAPS;
		if ((rdb_flags & RDB_FL_EVENTS) == 0)
			return;

		(void) printf("dlactivity: state changed to: ");
		switch (emt.u.state) {
		case RD_CONSISTENT:
			(void) printf("RD_CONSISTENT\n");
			break;
		case RD_ADD:
			(void) printf("RD_ADD\n");
			break;
		case RD_DELETE:
			(void) printf("RD_DELETE\n");
			break;
		default:
			(void) printf("unknown: 0x%x\n", emt.u.state);
		}
		return;
	}

	if ((rdb_flags & RDB_FL_EVENTS) == 0)
		return;

	if (emt.type == RD_PREINIT) {
		(void) printf("preinit reached\n");
		return;
	}

	if (emt.type == RD_POSTINIT)
		(void) printf("postinit reached\n");
}

unsigned
continue_to_break(struct ps_prochandle *ph)
{
	bptlist_t	*bpt;
	pstatus_t	pstatus;
	struct iovec	piov[5];
	long		oper1, oper2, oper3, pflags = 0;
	fltset_t	faults;

	/*
	 * We step by the first instruction incase their was
	 * a break-point there.
	 */
	(void) step_n(ph, 1, FLG_SN_NONE);

	premptyset(&faults);
	praddset(&faults, FLTBPT);
	praddset(&faults, FLTILL);
	praddset(&faults, FLTPRIV);
	praddset(&faults, FLTACCESS);
	praddset(&faults, FLTBOUNDS);
	praddset(&faults, FLTIZDIV);
	praddset(&faults, FLTSTACK);
	praddset(&faults, FLTTRACE);


	/* LINTED CONSTANT */
	while (1) {
		set_breaks(ph);
		oper1 = PCSFAULT;
		piov[0].iov_base = (caddr_t)(&oper1);
		piov[0].iov_len = sizeof (oper1);

		piov[1].iov_base = (caddr_t)(&faults);
		piov[1].iov_len = sizeof (faults);

		oper2 = PCRUN;
		piov[2].iov_base = (caddr_t)(&oper2);
		piov[2].iov_len = sizeof (oper2);
		pflags = PRCFAULT;
		piov[3].iov_base = (caddr_t)(&pflags);
		piov[3].iov_len = sizeof (pflags);

		oper3 = PCWSTOP;
		piov[4].iov_base = (caddr_t)(&oper3);
		piov[4].iov_len = sizeof (oper3);

		if (writev(ph->pp_ctlfd, piov, 5) == -1) {
			if (errno == ENOENT) {
				ph->pp_flags &= ~FLG_PP_PACT;

				(void) ps_close(ph);
				(void) printf("process terminated.\n");
				return (0);
			}
			perr("ctb: PCWSTOP");
		}

		if (pread(ph->pp_statusfd, &pstatus, sizeof (pstatus), 0) == -1)
			perr("ctb: reading status");


		if ((pstatus.pr_lwp.pr_why != PR_FAULTED) ||
		    (pstatus.pr_lwp.pr_what != FLTBPT)) {
			const char	*fltmsg;

			if ((pstatus.pr_lwp.pr_what <= MAXFAULT) &&
			    (pstatus.pr_lwp.pr_why == PR_FAULTED))
				fltmsg = fault_strings[pstatus.pr_lwp.pr_what];
			else
				fltmsg = "<unknown error>";

			(void) fprintf(stderr, "ctb: bad stop - stopped "
			    "on why: 0x%x what: %s(0x%x)\n",
			    pstatus.pr_lwp.pr_why, fltmsg,
			    pstatus.pr_lwp.pr_what);
			return (0);
		}

		oper1 = PCCFAULT;
		if (writev(ph->pp_ctlfd, piov, 1) == -1)
			perr("ctb: PCCFAULT");

		if ((bpt = find_bp(ph, pstatus.pr_lwp.pr_reg[R_PC])) ==
		    (bptlist_t *)-1) {
			(void) fprintf(stderr,
			    "stopped at unregistered breakpoint! "
			    "addr: 0x%x\n",
			    EC_WORD(pstatus.pr_lwp.pr_reg[R_PC]));
			break;
		}
		clear_breaks(ph);

		/*
		 * If this was a BP at which we should stop
		 */
		if (bpt->bl_flags & MASK_BP_STOP)
			break;

		(void) step_n(ph, 1, FLG_SN_NONE);
	}

	if (bpt->bl_flags & FLG_BP_USERDEF)
		(void) printf("break point reached at addr: 0x%x\n",
		    EC_WORD(pstatus.pr_lwp.pr_reg[R_PC]));

	if (bpt->bl_flags & MASK_BP_SPECIAL)
		handle_sp_break(ph);

	if (ph->pp_flags & FLG_PP_LMAPS) {
		if (get_linkmaps(ph) != RET_OK)
			(void) fprintf(stderr, "problem loading linkmaps\n");
	}

	return (bpt->bl_flags);
}

ulong_t
is_plt(struct ps_prochandle *ph, ulong_t pc)
{
	map_info_t	*mip;
	ulong_t		pltbase;

	if ((mip = addr_to_map(ph, pc)) == (map_info_t *)0)
		return ((ulong_t)0);

	pltbase = mip->mi_pltbase;
	if ((mip->mi_flags & FLG_MI_EXEC) == 0)
		pltbase += mip->mi_addr;

	if ((pc >= pltbase) && (pc <= (pltbase + mip->mi_pltsize)))
		return (pltbase);

	return ((ulong_t)0);
}

retc_t
step_n(struct ps_prochandle *ph, size_t count, sn_flags_e flgs)
{
	pstatus_t	pstatus;
	fltset_t	faults;
	int		i;
	long		oper;
	long		flags;
	struct iovec	piov[2];

	if (pread(ph->pp_statusfd, &pstatus, sizeof (pstatus), 0) == -1)
		perr("stn: reading status");

	piov[0].iov_base = (caddr_t)(&oper);
	piov[0].iov_len = sizeof (oper);

	premptyset(&faults);
	praddset(&faults, FLTTRACE);

	flags = PRSTEP | PRCFAULT;

	for (i = 0; i < count; i++) {
		bptlist_t	*bpt;
		uintptr_t	pc, pltbase;

		pc = pstatus.pr_lwp.pr_reg[R_PC];

		if ((bpt = find_bp(ph, pc)) != (bptlist_t *)-1) {
			if (bpt->bl_flags & MASK_BP_SPECIAL)
				handle_sp_break(ph);
		}

		if (flgs & FLG_SN_VERBOSE)
			disasm(ph, 1);

		oper = PCSFAULT;
		piov[1].iov_base = (caddr_t)(&faults);
		piov[1].iov_len = sizeof (faults);

		if (writev(ph->pp_ctlfd, piov, 2) == -1)
			perr("stn: PCSFAULT");

		oper = PCRUN;
		piov[1].iov_base = (caddr_t)(&flags);
		piov[1].iov_len = sizeof (flags);
		if (writev(ph->pp_ctlfd, piov, 2) == -1)
			perr("stn: PCRUN(PRSETP)");

		oper = PCWSTOP;
		if (writev(ph->pp_ctlfd, piov, 1) == -1)
			perr("stn: PCWSTOP stepping");

		if (pread(ph->pp_statusfd, &pstatus, sizeof (pstatus), 0) == -1)
			perr("stn1: reading status");
		pc = pstatus.pr_lwp.pr_reg[R_PC];


		if ((pstatus.pr_lwp.pr_why != PR_FAULTED) ||
		    (pstatus.pr_lwp.pr_what != FLTTRACE)) {
			(void) fprintf(stderr, "sn: bad stop - stopped on "
			    "why: 0x%x what: 0x%x\n", pstatus.pr_lwp.pr_why,
			    pstatus.pr_lwp.pr_what);
			return (RET_FAILED);
		}

		if ((flgs & FLG_SN_PLTSKIP) &&
		    ((pltbase = is_plt(ph, pc)) != (ulong_t)0)) {
			rd_plt_info_t	rp;
			if (rd_plt_resolution(ph->pp_rap, pc,
			    pstatus.pr_lwp.pr_lwpid, pltbase, &rp) != RD_OK) {
				(void) fprintf(stderr,
				    "sn: rd_plt_resolution failed\n");
				return (RET_FAILED);
			}
			if (rp.pi_skip_method == RD_RESOLVE_TARGET_STEP) {
				unsigned	bpflags;

				(void) set_breakpoint(ph, rp.pi_target,
				    FLG_BP_PLTRES);
				bpflags = continue_to_break(ph);

				(void) delete_breakpoint(ph, rp.pi_target,
				    FLG_BP_PLTRES);

				if (bpflags & FLG_BP_PLTRES)
					(void) step_n(ph, rp.pi_nstep,
					    FLG_SN_NONE);
			} else if (rp.pi_skip_method == RD_RESOLVE_STEP)
				(void) step_n(ph, rp.pi_nstep, FLG_SN_NONE);
		}
	}

	oper = PRCFAULT;
	if (writev(ph->pp_ctlfd, piov, 1) == -1)
		perr("stn: PRCFAULT");

	if ((flgs & FLG_SN_VERBOSE) && (ph->pp_flags & FLG_PP_LMAPS)) {
		if (get_linkmaps(ph) != RET_OK)
			(void) fprintf(stderr, "problem loading linkmaps\n");
	}

	return (RET_OK);
}

void
step_to_addr(struct ps_prochandle *ph, ulong_t addr)
{
	pstatus_t	pstat;
	int		count = 0;
	ulong_t		caddr;

	if (read(ph->pp_statusfd, &pstat, sizeof (pstat)) == -1)
		perr("sta: reading status");

	caddr = pstat.pr_lwp.pr_reg[R_PC];

	while ((caddr > addr) || ((caddr + 0xff) < addr)) {
		(void) step_n(ph, 1, FLG_SN_NONE);
		if (read(ph->pp_statusfd, &pstat, sizeof (pstat)) == -1)
			perr("sta1: reading status");
		caddr = pstat.pr_lwp.pr_reg[R_PC];
		if ((count % 10000) == 0) {
			(void) printf("%d: ", count);
			disasm(ph, 1);
		}

		count++;
	}

	(void) printf("address found %d instructions in: pc: 0x%lx addr: "
	    "0x%lx\n", count, caddr, addr);
}
