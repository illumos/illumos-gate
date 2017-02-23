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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/open.h>
#include <sys/param.h>
#include <sys/vm_machparam.h>
#include <sys/machparam.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/poll.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/x_call.h>
#include <sys/cpuvar.h>
#include <sys/machcpuvar.h>
#include <sys/machsystm.h>

#include <sys/pda.h>
#include <sys/starfire.h>
#include <sys/idn.h>
#include <sys/idn_xf.h>

kmutex_t	idn_xf_mutex;		/* to serialize hardware access */
/*
 * This data structure is referenced during the cross-call
 * update of the CICs.  The semaphore is used for synchronization
 * when waiting for completion of the respective operation.
 * We want IDNCIC_TIMEOUT ticks for all the cpus to check-in
 * before we bail out and fail the operation.
 */
#define	IDNCIC_TIMEOUT		(30*hz)
#define	IDNCIC_TIMECHK		(hz/3)
#define	IDNCIC_UNKNOWN		0
#define	IDNCIC_OK		1	/* values for xf_errcic */
#define	IDNCIC_ERR		2
#define	IDNCIC_BUSY		3

#ifdef DEBUG
#define	NCICREGS		3	/* smmask, smbar, smlar */
#define	CICREG_SMMASK		0
#define	CICREG_SMBAR		1
#define	CICREG_SMLAR		2

#define	RESET_CIC_HISTORY() \
		(xf_cicboards = xf_cicbuses = 0, \
		bzero(xf_cicregs, sizeof (xf_cicregs)))

#define	UPDATE_CIC_HISTORY(reg, brd, bus, val) \
		(BOARDSET_ADD(xf_cicboards, (brd)), \
		BOARDSET_ADD(xf_cicbuses, (bus)), \
		xf_cicregs[brd][bus][reg] = (val))

#define	DUMP_CIC_HISTORY() \
{ \
	if (idn_debug & IDNDBG_XF) { \
		int	_bd, _bs; \
		procname_t	_proc = "dump_cic_history"; \
		for (_bd = 0; _bd < MAX_BOARDS; _bd++) { \
			if (!BOARD_IN_SET(xf_cicboards, _bd)) \
				continue; \
			for (_bs = 0; _bs < MAX_ABUSES; _bs++) { \
				if (!BOARD_IN_SET(xf_cicbuses, _bs)) \
					continue; \
				printf("%s: (bd.bs = %d.%d) m/b/l = " \
					"%x/%x/%x\n", _proc, _bd, _bs, \
					xf_cicregs[_bd][_bs][CICREG_SMMASK], \
					xf_cicregs[_bd][_bs][CICREG_SMBAR], \
					xf_cicregs[_bd][_bs][CICREG_SMLAR]); \
			} \
		} \
		DEBUG_DELAY(); \
	} \
}

/*
 * Globally updated during CIC reg updates.  Everybody has
 * a unique location, so no concern about updates stepping
 * on each other.
 */
static ushort_t	xf_cicboards, xf_cicbuses;
static uint_t	xf_cicregs[MAX_BOARDS][MAX_ABUSES][NCICREGS];
#else /* DEBUG */
#define	RESET_CIC_HISTORY()
#define	UPDATE_CIC_HISTORY(reg, brd, bus, val)
#define	DUMP_CIC_HISTORY()
#endif /* DEBUG */

struct idnxf_cic_info {			/* protected by idn_xf_mutex */
/*  0 */	short		xf_abus_mask;
/*  2 */	boardset_t	xf_boardset;
/*  4 */	uint_t		xf_smbase;
/*  8 */	uint_t		xf_smlimit;
/*  c */	int		xf_doadd;

/* 10 */	int		xf_count;	/* atomically updated */
/* 14 */	time_t		xf_start_time;
/* 18 */	kcondvar_t	xf_cv;
/* 1a */	short		xf_errtimer;
/* 1c */	int		xf_errcnt;	/* atomically updated */

/* 20 */	uchar_t		xf_errcic[MAX_BOARDS][MAX_ABUSES];

/* 60 */	kmutex_t	xf_mutex;
};	/* sizeof = 0x68 = 104 (26X) */

static struct idnxf_cic_info	idnxf_cic_info;
#ifdef DEBUG
static uint_t			o_idn_debug;
#endif /* DEBUG */

int	idn_check_cpu_per_board = 1;

static int	pc_prep_cic_buffer(int cpuid, uint_t cicdata);
static int	cic_write_sm_mask(int board, int bus, boardset_t sm_mask);
static int	cic_write_sm_bar(int board, int bus, uint_t sm_bar);
static int	cic_write_sm_lar(int board, int bus, uint_t sm_lar);
static int	cic_get_smmask_bit(void);
static int	pc_write_madr(pda_handle_t ph,
				int lboard, int rboard, uint_t madr);
static boardset_t	get_boardset(pda_handle_t ph, int *nboards);
static int	verify_smregs(int brd, int bus, boardset_t smmask,
				uint_t smbase, uint_t smlimit);
static void	idnxf_shmem_wakeup(void *arg);
static void	idnxf_shmem_update_one(uint64_t arg1, uint64_t arg2);
static int	idnxf_shmem_update_all(pda_handle_t ph,
				boardset_t boardset, uint_t smbase,
				uint_t smlimit, int doadd);

#define	PHYSIO_ST(paddr, val)		(stphysio((paddr), (val)))
#define	PHYSIO_LD(paddr)		(ldphysio(paddr))
#define	PHYSIO_STH(paddr, val)		(sthphysio((paddr), (val)))
#define	PHYSIO_LDH(paddr)		(ldhphysio(paddr))

#ifdef DEBUG
#define	DEBUG_DELAY() 	(drv_usecwait(5000))	/* 5 ms */
#else /* DEBUG */
#define	DEBUG_DELAY()
#endif /* DEBUG */


/*
 * ---------------------------------------------------------------------
 */
boardset_t
cic_read_domain_mask(int board, int bus)
{
	u_longlong_t	csr_addr;
	boardset_t	domain_mask;
	procname_t	proc = "cic_read_domain_mask";

	ASSERT(CPUID_TO_BOARDID(CPU->cpu_id) == board);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_DOMAIN_MASK_ADDR,
	    bus);
	PR_XF("%s: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);

	domain_mask = (boardset_t)PHYSIO_LDH(csr_addr);

	return (domain_mask);
}

boardset_t
cic_read_sm_mask(int board, int bus)
{
	u_longlong_t	csr_addr;
	boardset_t	sm_mask;
	procname_t	proc = "cic_read_sm_mask";

	ASSERT(CPUID_TO_BOARDID(CPU->cpu_id) == board);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_MASK_ADDR,
	    bus);
	PR_XF("%s: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);

	sm_mask = (boardset_t)PHYSIO_LDH(csr_addr);

	return (sm_mask);
}

static int
cic_write_sm_mask(int board, int bus, boardset_t sm_mask)
{
	u_longlong_t	csr_addr;
	int		cnt;
	procname_t	proc = "cic_write_sm_mask";

	ASSERT(CPUID_TO_BOARDID(CPU->cpu_id) == board);

	sm_mask &= 0xffff;
	/*
	 * Before we can write to the CIC, we need to set
	 * up the CIC write data buffer in the PC.
	 */
	if (pc_prep_cic_buffer(CPU->cpu_id, (uint_t)sm_mask) < 0)
		return (-1);

	/*
	 * Now we can write to the CIC.
	 */
	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_MASK_ADDR,
	    bus);
	PR_XF("%s: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);
	PR_XF("%s: writing sm_mask = 0x%x\n",
	    proc, (ushort_t)sm_mask);

	UPDATE_CIC_HISTORY(CICREG_SMMASK, board, bus, sm_mask);

	PHYSIO_STH(csr_addr, (ushort_t)sm_mask);
	/*
	 * Read back for verification.
	 */
	for (cnt = 0; (PHYSIO_LDH(csr_addr) != sm_mask) && (cnt < 10); cnt++)
		;

	return ((cnt == 10) ? -1 : 0);
}

uint_t
cic_read_sm_bar(int board, int bus)
{
	u_longlong_t	csr_addr;
	uint_t		sm_bar;
	procname_t	proc = "cic_read_sm_bar";

	ASSERT(CPUID_TO_BOARDID(CPU->cpu_id) == board);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_BAR_MSB_ADDR,
	    bus);
	PR_XF("%s:MSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);

	sm_bar = (uint_t)PHYSIO_LDH(csr_addr);
	sm_bar <<= 16;

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_BAR_LSB_ADDR,
	    bus);
	PR_XF("%s:LSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);

	sm_bar |= (uint_t)PHYSIO_LDH(csr_addr);

	return (sm_bar);
}

static int
cic_write_sm_bar(int board, int bus, uint_t sm_bar)
{
	int		cnt;
	u_longlong_t	csr_addr;
	uint_t		sm_bar_lsb, sm_bar_msb;
	procname_t	proc = "cic_write_sm_bar";

	ASSERT(CPUID_TO_BOARDID(CPU->cpu_id) == board);

	sm_bar_lsb = sm_bar & 0xffff;
	sm_bar_msb = (sm_bar >> 16) & 0xffff;

	/*
	 * Before we can write to the CIC, we need to set
	 * up the CIC write data buffer in the PC.
	 */
	if (pc_prep_cic_buffer(CPU->cpu_id, sm_bar_msb) < 0)
		return (-1);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_BAR_MSB_ADDR,
	    bus);
	PR_XF("%s:MSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);
	PR_XF("%s:MSB: sm_bar[31:16] = 0x%x\n",
	    proc, (ushort_t)sm_bar_msb);

	UPDATE_CIC_HISTORY(CICREG_SMBAR, board, bus, sm_bar);

	PHYSIO_STH(csr_addr, (ushort_t)sm_bar_msb);
	for (cnt = 0;
	    ((uint_t)PHYSIO_LDH(csr_addr) != sm_bar_msb) && (cnt < 10);
	    cnt++)
		;
	if (cnt == 10) {
		cmn_err(CE_WARN,
		    "IDN: 500: failed to write sm_bar (msb) (0x%x)",
		    (uint_t)sm_bar_msb);
		return (-1);
	}

	/*
	 * Now to LSB portion.
	 */
	if (pc_prep_cic_buffer(CPU->cpu_id, sm_bar_lsb) < 0)
		return (-1);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_BAR_LSB_ADDR,
	    bus);
	PR_XF("%s:LSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);
	PR_XF("%s:LSB: sm_bar[15:0] = 0x%x\n",
	    proc, (ushort_t)sm_bar_lsb);

	PHYSIO_STH(csr_addr, (ushort_t)sm_bar_lsb);
	for (cnt = 0;
	    ((uint_t)PHYSIO_LDH(csr_addr) != sm_bar_lsb) && (cnt < 10);
	    cnt++)
		;
	if (cnt == 10) {
		cmn_err(CE_WARN,
		    "IDN: 500: failed to write sm_bar (lsb) (0x%x)",
		    (uint_t)sm_bar_lsb);
		return (-1);
	}

	return (0);
}

uint_t
cic_read_sm_lar(int board, int bus)
{
	u_longlong_t	csr_addr;
	uint_t		sm_lar;
	procname_t	proc = "cic_read_sm_lar";

	ASSERT(CPUID_TO_BOARDID(CPU->cpu_id) == board);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_LAR_MSB_ADDR,
	    bus);
	PR_XF("%s:MSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);

	sm_lar = (uint_t)PHYSIO_LDH(csr_addr);
	sm_lar <<= 16;

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_LAR_LSB_ADDR,
	    bus);
	PR_XF("%s:LSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);

	sm_lar |= (uint_t)PHYSIO_LDH(csr_addr);

	return (sm_lar);
}

static int
cic_write_sm_lar(int board, int bus, uint_t sm_lar)
{
	int		cnt;
	u_longlong_t	csr_addr;
	uint_t		sm_lar_lsb, sm_lar_msb;
	procname_t	proc = "cic_write_sm_lar";

	ASSERT(CPUID_TO_BOARDID(CPU->cpu_id) == board);

	sm_lar_lsb = sm_lar & 0xffff;
	sm_lar_msb = (sm_lar >> 16) & 0xffff;

	/*
	 * Before we can write to the CIC, we need to set
	 * up the CIC write data buffer in the PC.
	 */
	if (pc_prep_cic_buffer(CPU->cpu_id, sm_lar_msb) < 0)
		return (-1);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_LAR_MSB_ADDR,
	    bus);
	PR_XF("%s:MSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);
	PR_XF("%s:MSB: sm_lar[31:16] = 0x%x\n",
	    proc, (ushort_t)sm_lar_msb);

	UPDATE_CIC_HISTORY(CICREG_SMLAR, board, bus, sm_lar);

	PHYSIO_STH(csr_addr, (ushort_t)sm_lar_msb);
	for (cnt = 0;
	    ((uint_t)PHYSIO_LDH(csr_addr) != sm_lar_msb) && (cnt < 10);
	    cnt++)
		;
	if (cnt == 10) {
		cmn_err(CE_WARN,
		    "IDN: 501: failed to write sm_lar (msb) (0x%x)",
		    (uint_t)sm_lar_msb);
		return (-1);
	}

	/*
	 * Now to LSB portion.
	 */
	if (pc_prep_cic_buffer(CPU->cpu_id, sm_lar_lsb) < 0)
		return (-1);

	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_SM_LAR_LSB_ADDR,
	    bus);
	PR_XF("%s:LSB: (bd=%d, bs=%d) csr_addr = 0x%llx\n",
	    proc, board, bus, csr_addr);
	PR_XF("%s:LSB: sm_lar[15:0] = 0x%x\n",
	    proc, (ushort_t)sm_lar_lsb);

	PHYSIO_STH(csr_addr, (ushort_t)sm_lar_lsb);
	for (cnt = 0;
	    ((uint_t)PHYSIO_LDH(csr_addr) != sm_lar_lsb) && (cnt < 10);
	    cnt++)
		;
	if (cnt == 10) {
		cmn_err(CE_WARN,
		    "IDN: 501: failed to write sm_lar (lsb) (0x%x)",
		    (uint_t)sm_lar_lsb);
		return (-1);
	}

	return (0);
}

static int
cic_get_smmask_bit(void)
{
	u_longlong_t	csr_addr;
	int		board;
	uint_t		config1;
	procname_t	proc = "cic_get_smmask_bit";

	affinity_set(CPU_CURRENT);

	board = CPUID_TO_BOARDID(CPU->cpu_id);
	/*
	 * Now that I'm stuck on this cpu I can go look at this
	 * board's CIC registers.
	 */
	csr_addr = MAKE_CIC_CSR_PA(board, CSR_TYPE_CIC, CIC_CONFIG1_ADDR, 0);
	PR_XF("%s: (bd=%d) csr_addr = 0x%llx (via cpu %d)\n",
	    proc, board, csr_addr, (int)CPU->cpu_id);

	config1 = (uint_t)PHYSIO_LDH(csr_addr);

	config1 = CIC_CONFIG1_SMMASK_BIT(config1);

	affinity_clear();

	return (config1);
}

static int
pc_prep_cic_buffer(int cpuid, uint_t cicdata)
{
	int		rv;
	int		brd, port;
	u_longlong_t	csr_addr;
	register int	cnt;
	procname_t	proc = "pc_prep_cic_buffer";


	ASSERT(CPU->cpu_id == cpuid);

	port = cpuid % plat_max_cpu_units_per_board();
	brd = CPUID_TO_BOARDID(cpuid);

	csr_addr = STARFIRE_PC_CICBUF_ADDR(brd, port);

	/*
	 * csr_addr now points to CIC write buffer which resides
	 * in PC register space.
	 */
	PR_XF("%s: (cpu=%d) csr_addr = 0x%llx\n", proc, cpuid, csr_addr);

	PHYSIO_ST(csr_addr, cicdata);

	/*
	 * Now we need to read back the data to guarantee
	 * it got there.  Part of the PC protocol.
	 */
	for (cnt = 0; (PHYSIO_LD(csr_addr) != cicdata) && (cnt < 10);
	    cnt++)
		;

	rv = 0;
	if (cnt == 10) {
		cmn_err(CE_WARN,
		    "IDN: 502: unable to store data (0x%x) to "
		    "CIC buffer (0x%llx)",
		    cicdata, csr_addr);
		rv = -1;
	} else if (cnt >= 1) {
		PR_XF("%s: MULTIPLE READS (cpu=%d) cnt = %d\n",
		    proc, cpuid, cnt);
	}

	return (rv);
}

/*
 * --------------------------------------------------
 * Write the given MC address decoding register contents (madr) of
 * the respective remote board (rboard) into all the PCs located on
 * the local board (lboard).
 * --------------------------------------------------
 */
static int
pc_write_madr(pda_handle_t ph, int lboard, int rboard, uint_t madr)
{
	u_longlong_t	pc_madr_addr;
	register int	p, ioc;
	register ushort_t	procset, iocset;
	int		rv = 0;
	uint_t		rd_madr;
	board_desc_t	*lbp;
	procname_t	proc = "pc_write_madr";

	lbp = pda_get_board_info(ph, lboard);

	ASSERT(lbp);
	ASSERT((lbp->bda_board & BDAN_MASK) == BDAN_GOOD);

	procset = lbp->bda_proc;
	iocset  = lbp->bda_ioc;

	/*
	 * Update the PCs for the cpus.
	 */
	for (p = 0; p < MAX_PROCMODS; procset >>= 4, p++) {
		int	i;

		if (!((procset & BDAN_MASK) == BDAN_GOOD))
			continue;

		pc_madr_addr = (u_longlong_t)STARFIRE_PC_MADR_ADDR(lboard,
		    rboard, p);

		/*
		 * On this first iteration of updating the PC
		 * we need to turn off the MADR VALID bit so that
		 * there's no accidental usage of the entry before
		 * all four bytes have been updated in the PC.
		 */
		if (madr != 0) {
			/*
			 * Need to clear valid bit on first
			 * go around.
			 */
			madr &= ~STARFIRE_PC_MADR_VALIDBIT;
		}
		PR_XF("%s: write madr(0x%x) to pc_addr(0x%llx) "
		    "[lb=%d, rb=%d, cpu=%d]\n",
		    proc, madr, pc_madr_addr, lboard, rboard, p);
		DEBUG_DELAY();

		for (i = 0; i < 20; i++) {
			PHYSIO_ST(pc_madr_addr, madr);
			/*
			 * Read back for sanity check.
			 */
			rd_madr = PHYSIO_LD(pc_madr_addr);
			if (madr == rd_madr)
				break;
		}
		if (i > 0) {
			PR_XF("%s: WARNING: (1) lb=%d, rb=%d, "
			    "madr=0x%x (i=%d)\n",
			    proc, lboard, rboard, madr, i);
		}
		if (rd_madr != madr) {
			cmn_err(CE_WARN,
			    "IDN: 503: (invalidate) failed to update "
			    "PC madr (expected 0x%x, actual 0x%x)",
			    madr, rd_madr);
			rv++;
			continue;
		}
		if (madr == 0) {
			continue;
		} else {
			/*
			 * Turn the valid bit back on.
			 */
			madr |= STARFIRE_PC_MADR_VALIDBIT;
		}
		PR_XF("%s: write madr(0x%x) to pc_addr(0x%llx) "
		    "[lb=%d, rb=%d, cpu=%d]\n",
		    proc, madr, pc_madr_addr, lboard, rboard, p);
		DEBUG_DELAY();

		for (i = 0; i < 20; i++) {
			PHYSIO_ST(pc_madr_addr, madr);
			/*
			 * Read back for sanity check.
			 */
			rd_madr = PHYSIO_LD(pc_madr_addr);
			if (madr == rd_madr)
				break;
		}
		if (i > 0) {
			PR_XF("%s: WARNING: (2) lb=%d, rb=%d, "
			    "madr=0x%x (i=%d)\n",
			    proc, lboard, rboard, madr, i);
		}
		if (rd_madr != madr) {
			cmn_err(CE_WARN,
			    "IDN: 503: (validate) failed to update "
			    "PC madr (expected 0x%x, actual 0x%x)",
			    madr, rd_madr);
			rv++;
		}
	}
	/*
	 * Update the PCs for the iocs.
	 */
	for (ioc = 0; ioc < MAX_IOCS; iocset >>= 4, ioc++) {
		int	i;

		if (!((iocset & BDAN_MASK) == BDAN_GOOD))
			continue;

		pc_madr_addr = (u_longlong_t)STARFIRE_PC_MADR_ADDR(lboard,
		    rboard, ioc + 4);

		if (madr != 0) {
			/*
			 * Need to clear valid bit on first
			 * go around.
			 */
			madr &= ~STARFIRE_PC_MADR_VALIDBIT;
		}
		PR_XF("%s: write madr(0x%x) to iopc_madr_addr(0x%llx) "
		    "[lb=%d, rb=%d, ioc=%d]\n",
		    proc, madr, pc_madr_addr, lboard, rboard, ioc);
		DEBUG_DELAY();

		for (i = 0; i < 20; i++) {
			PHYSIO_ST(pc_madr_addr, madr);
			/*
			 * Read back for sanity check.
			 */
			rd_madr = PHYSIO_LD(pc_madr_addr);
			if (madr == rd_madr)
				break;
		}
		if (i > 0) {
			PR_XF("%s: WARNING: (3) lb=%d, rb=%d, "
			    "madr=0x%x (i=%d)\n",
			    proc, lboard, rboard, madr, i);
		}
		if (rd_madr != madr) {
			cmn_err(CE_WARN,
			    "IDN: 504: (invalidate) failed to update "
			    "IOPC madr (expected 0x%x, actual 0x%x)",
			    madr, rd_madr);
			rv++;
			continue;
		}

		if (madr == 0) {
			continue;
		} else {
			/*
			 * Turn the valid bit back on.
			 */
			madr |= STARFIRE_PC_MADR_VALIDBIT;
		}

		PR_XF("%s: write madr(0x%x) to iopc_madr_addr(0x%llx) "
		    "[lb=%d, rb=%d, ioc=%d]\n",
		    proc, madr, pc_madr_addr, lboard, rboard, ioc);
		DEBUG_DELAY();

		for (i = 0; i < 20; i++) {
			PHYSIO_ST(pc_madr_addr, madr);
			/*
			 * Read back for sanity check.
			 */
			rd_madr = PHYSIO_LD(pc_madr_addr);
			if (madr == rd_madr)
				break;
		}
		if (i > 0) {
			PR_XF("%s: WARNING: (4) lb=%d, rb=%d, "
			    "madr=0x%x (i=%d)\n",
			    proc, lboard, rboard, madr, i);
		}
		if (rd_madr != madr) {
			cmn_err(CE_WARN,
			    "IDN: 504: (validate) failed to update "
			    "IOPC madr (expected 0x%x, actual 0x%x)",
			    madr, rd_madr);
			rv++;
		}
	}

	return (rv ? -1 : 0);
}

/*
 * --------------------------------------------------
 * Read the array of MC address decoding registers from one of the
 * PCs on the local board (lboard) into the given in array (mc_adr).
 * --------------------------------------------------
 */
void
pc_read_madr(pda_handle_t ph, int lboard, uint_t mc_adr[], int local_only)
{
	u_longlong_t	pc_madr_addr;
	register int	p, ioc;
	register ushort_t	procset, iocset;
	int		brd;
	board_desc_t	*lbp;

	lbp = pda_get_board_info(ph, lboard);

	ASSERT(lbp);
	ASSERT((lbp->bda_board & BDAN_MASK) == BDAN_GOOD);

	procset = lbp->bda_proc;
	iocset = lbp->bda_ioc;

	for (p = 0; p < MAX_PROCMODS; procset >>= 4, p++)
		if ((procset & BDAN_MASK) == BDAN_GOOD)
			break;

	if (p == MAX_PROCMODS) {
		/*
		 * Couldn't find a PC off a cpu, let's check the
		 * IOCs.
		 */
		for (ioc = 0; ioc < MAX_IOCS; iocset >>= 4, ioc++)
			if ((iocset & BDAN_MASK) == BDAN_GOOD)
				break;
		if (ioc == MAX_IOCS) {
			cmn_err(CE_WARN,
			    "IDN: 505: board %d missing any valid PCs",
			    lboard);
			return;
		}
		p = ioc + 4;
	}

	pc_madr_addr = (u_longlong_t)STARFIRE_PC_MADR_ADDR(lboard, 0, p);
	/*
	 * pc_madr_addr = Starts at entry for board 0.
	 */
	for (brd = 0; brd < MAX_BOARDS; brd++) {
		/*
		 * It's possible our local PC may have old entries to
		 * AWOL domains.  Only want to pay attention to PC
		 * entries corresponding to our boards.
		 */
		lbp = pda_get_board_info(ph, brd);
		if (!local_only || ((lbp->bda_board & BDAN_MASK) == BDAN_GOOD))
			mc_adr[brd] = PHYSIO_LD(pc_madr_addr);
		else
			mc_adr[brd] = 0;

		pc_madr_addr += ((u_longlong_t)1 <<
		    STARFIRE_PC_MADR_BOARD_SHIFT);
	}
}

/*
 * --------------------------------------------------
 * Read the MC address decoding register contents for all
 * possible boards and store the results in their respective
 * slot in mc_adr.  Keep a count of non-zero MC ADRs and
 * return that.
 * --------------------------------------------------
 */
void
mc_get_adr_all(pda_handle_t ph, uint_t mc_adr[], int *nmcadr)
{
	int	brd;
	uint_t	madr[MAX_BOARDS];

	/*
	 * Note that each PC has a complete copy of all MC contents
	 * and so all we have to do is read one PC rather than
	 * each of the MCs in the system.
	 */
	brd = CPUID_TO_BOARDID(CPU->cpu_id);
	pc_read_madr(ph, brd, madr, 1);

	*nmcadr = 0;
	for (brd = 0; brd < MAX_BOARDS; brd++)
		if ((mc_adr[brd] = madr[brd]) != 0)
			(*nmcadr)++;
}

static boardset_t
get_boardset(pda_handle_t ph, int *nboards)
{
	int		brd;
	int		nbrds = 0;
	boardset_t	bmask;

	if (nboards != NULL)
		*nboards = 0;

	bmask = 0;
	for (brd = 0; brd < MAX_BOARDS; brd++) {
		if (pda_board_present(ph, brd)) {
			bmask |= 1 << brd;
			nbrds++;
		}
	}
	if (nboards != NULL)
		*nboards = (short)nbrds;

	return (bmask);
}

int
update_local_hw_config(idn_domain_t *ldp, struct hwconfig *loc_hw)
{
	procname_t	proc = "update_local_hw_config";

	ASSERT(IDN_DLOCK_IS_EXCL(ldp->domid));
	ASSERT(IDN_GLOCK_IS_EXCL());
	ASSERT(ldp == &idn_domain[idn.localid]);

	if (ldp->dhw.dh_boardset != loc_hw->dh_boardset) {
		int	c;

		PR_PROTO("%s: NEW HW CONFIG (old_bset = 0x%x, "
		    "new_bset = 0x%x)\n",
		    proc, ldp->dhw.dh_boardset, loc_hw->dh_boardset);

		PR_PROTO("%s: clearing boardset 0x%x\n", proc,
		    ldp->dhw.dh_boardset & ~loc_hw->dh_boardset);
		PR_PROTO("%s: setting boardset  0x%x\n", proc,
		    loc_hw->dh_boardset & ~ldp->dhw.dh_boardset);

		idn.dc_boardset &= ~ldp->dhw.dh_boardset;
		idn.dc_boardset |= loc_hw->dh_boardset;
		for (c = 0; c < NCPU; c++) {
			if (CPU_IN_SET(ldp->dcpuset, c)) {
				CPUSET_DEL(idn.dc_cpuset, c);
			}
		}
		CPUSET_OR(idn.dc_cpuset, cpu_ready_set);

		bcopy(loc_hw, &ldp->dhw, sizeof (ldp->dhw));
		ldp->dcpuset = cpu_ready_set;
		ldp->dcpu    = cpu0.cpu_id;
		ldp->dncpus  = (int)ncpus;
		ldp->dvote.v.nmembrds = ldp->dhw.dh_nmcadr - 1;
		ldp->dvote.v.ncpus    = (int)ldp->dncpus - 1;
		ldp->dvote.v.board    = CPUID_TO_BOARDID(CPU->cpu_id);

		return (1);
	} else {
		PR_PROTO("%s: NO change detected\n", proc);
		return (0);
	}
}

int
get_hw_config(struct hwconfig *loc_hw)
{
	pda_handle_t	ph;
	boardset_t	domainset;
	int		bd;
	int		nmcadr;
	int		nboards;
	procname_t	proc = "get_hw_config";

	ASSERT(loc_hw != NULL);

	bzero(loc_hw, sizeof (*loc_hw));
	/*
	 * See if sm_mask is writable.
	 * XXX - Should be the same for all CIC's.  Do we
	 *	 we need to verify?
	 */
	if (cic_get_smmask_bit() == 0) {
		/*
		 * If smmask is not writable, we can not allow
		 * IDN operations.
		 */
		cmn_err(CE_WARN,
		    "IDN: 506: cic sm_mask is not writeable");
		return (-1);
	}
	/*
	 * Map in the post2obp structure so we can find
	 * valid boards and hardware asics.
	 */
	ph = pda_open();
	if (ph == (pda_handle_t)NULL) {
		cmn_err(CE_WARN,
		    "IDN: 507: failed to map-in post2obp structure");
		return (-1);
	} else if (!pda_is_valid(ph)) {
		cmn_err(CE_WARN, "IDN: 508: post2obp checksum invalid");
		pda_close(ph);
		return (-1);
	}
	/*
	 * Need to read the MC address decoding registers
	 * so that they can be given to other domains.
	 */
	loc_hw->dh_boardset = get_boardset(ph, &nboards);
	loc_hw->dh_nboards = (short)nboards;
	ASSERT(loc_hw->dh_boardset & (1 << CPUID_TO_BOARDID(CPU->cpu_id)));

	mc_get_adr_all(ph, loc_hw->dh_mcadr, &nmcadr);
	loc_hw->dh_nmcadr = (short)nmcadr;

	affinity_set(CPU_CURRENT);
	/*
	 * There will always be a bus 0 (logical).
	 */
	bd = CPUID_TO_BOARDID(CPU->cpu_id);
	domainset = (boardset_t)cic_read_domain_mask(bd, 0);
	affinity_clear();

	if (!idn_cpu_per_board(ph, cpu_ready_set, loc_hw)) {
		pda_close(ph);
		return (-1);
	}

	pda_close(ph);


#ifdef DEBUG
	{
		int	brd;

		for (brd = 0; brd < MAX_BOARDS; brd++)
			if (loc_hw->dh_mcadr[brd] != 0) {
				PR_XF("%s: brd %d, mc = 0x%x\n",
				    proc, brd, loc_hw->dh_mcadr[brd]);
			}
	}
#endif /* DEBUG */

	if ((loc_hw->dh_boardset != domainset) || (loc_hw->dh_nmcadr < 1))
		return (-1);
	else
		return (0);
}

/*
 * Function called via timeout() to wakeup a possibly stuck
 * idnxf_shmem_update_all() should not all cpus check-in after a
 * x-call to update their respective CICs.
 */
/*ARGSUSED0*/
static void
idnxf_shmem_wakeup(void *arg)
{
	struct idnxf_cic_info	*idnxfp = (struct idnxf_cic_info *)arg;
	int		count;
	int		expired;
	procname_t	proc = "idnxf_shmem_wakeup";

	expired = ((ddi_get_lbolt() - idnxfp->xf_start_time) >=
	    IDNCIC_TIMEOUT) ? 1 : 0;

	if ((count = idnxfp->xf_count) == 0) {
		/*
		 * Everybody has finished.  Wakeup the requester.
		 */
		mutex_enter(&idnxfp->xf_mutex);
		cv_signal(&idnxfp->xf_cv);
		mutex_exit(&idnxfp->xf_mutex);

	} else if ((count > 0) && expired) {
		/*
		 * There are still active cic updaters and time
		 * has expired.  Bail on them.
		 */
		idnxfp->xf_errtimer = 1;
#ifdef DEBUG
		/*
		 * Special debug case since idn_debug
		 * may have been temporarily cleared
		 * during xc_some.
		 */
		if ((idn_debug | o_idn_debug) & IDNDBG_REGS)
			printf("%s: TIMEOUT...bailing on %d lost CIC "
			    "updates...\n", proc, count);
#endif /* DEBUG */

		ATOMIC_SUB(idnxfp->xf_count, count);

		mutex_enter(&idnxfp->xf_mutex);
		cv_signal(&idnxfp->xf_cv);
		mutex_exit(&idnxfp->xf_mutex);

	} else {
		(void) timeout(idnxf_shmem_wakeup, (caddr_t)idnxfp,
		    (clock_t)IDNCIC_TIMECHK);
	}
}

/*
 * Called indirectly from idnxf_shmem_update_all() via a xcall
 * for the recepient cpu to update the CICs on its respective
 * board.
 * IMPORTANT: NO console output from this routine!!
 */
static void
idnxf_shmem_update_one(uint64_t arg1, uint64_t arg2)
{
	struct idnxf_cic_info	*idnxfp = (struct idnxf_cic_info *)arg1;
	time_t		start_time = (time_t)arg2;
	int		rv, cpuid, brd, bus;
	boardset_t	smmask;


	cpuid = CPU->cpu_id;
	brd   = CPUID_TO_BOARDID(cpuid);

	if (idnxfp->xf_start_time != start_time) {
		/*
		 * Ooops!  Not my place to intrude.
		 */
		idnxf_cic_info.xf_errcic[brd][0] = IDNCIC_BUSY;
		ATOMIC_INC(idnxf_cic_info.xf_errcnt);

		goto done;
	}

	/*
	 * We're executing out of the context of a cross-call
	 * so we're effectively bound! :)
	 */
	for (bus = 0; bus < MAX_ABUSES; bus++) {
		/*
		 * XXX - need to worry about shuffle??
		 */
		if (!(idnxfp->xf_abus_mask & (1 << bus)))
			continue;
		smmask = cic_read_sm_mask(brd, bus);

		if (idnxfp->xf_doadd) {
			smmask |= idnxfp->xf_boardset;
			(void) cic_write_sm_mask(brd, bus, smmask);

			if (idnxfp->xf_smbase != (uint_t)-1) {
				(void) cic_write_sm_bar(brd, bus,
				    idnxfp->xf_smbase);
				(void) cic_write_sm_lar(brd, bus,
				    idnxfp->xf_smlimit);
			}
			/*
			 * Verify data got there!
			 */
			rv = verify_smregs(brd, bus, smmask, idnxfp->xf_smbase,
			    idnxfp->xf_smlimit);
		} else {
			smmask &= ~idnxfp->xf_boardset;
			(void) cic_write_sm_mask(brd, bus, smmask);

			if (!smmask) {
				/*
				 * Update the LAR first so that we effectively
				 * disable the register without possibly
				 * opening the window to transaction we
				 * don't care about.  Updating the LAR first
				 * will guarantee we effectively turn it
				 * off immediately.
				 */
				(void) cic_write_sm_lar(brd, bus, 0);
				(void) cic_write_sm_bar(brd, bus, 1);

				rv = verify_smregs(brd, bus, smmask, 1, 0);
			} else {
				rv = verify_smregs(brd, bus, smmask,
				    (uint_t)-1, (uint_t)-1);
			}
		}
		if (rv) {
			idnxf_cic_info.xf_errcic[brd][bus] = IDNCIC_ERR;
			ATOMIC_INC(idnxf_cic_info.xf_errcnt);
		} else {
			idnxf_cic_info.xf_errcic[brd][bus] = IDNCIC_OK;
		}
	}

done:
	ATOMIC_DEC(idnxf_cic_info.xf_count);
}

static int
idnxf_shmem_update_all(pda_handle_t ph, boardset_t boardset,
			uint_t smbase, uint_t smlimit, int doadd)
{
	cpuset_t	target_cpuset;
	int		target_count;
	int		rv = 0;
	int		c, brd, bus;
	short		abus_mask;
	time_t		start_time;
	procname_t	proc = "idnxf_shmem_update_all";


	ASSERT(MUTEX_HELD(&idn_xf_mutex));

	pda_get_busmask(ph, &abus_mask, NULL);

	CPUSET_ZERO(target_cpuset);
	target_count = 0;
	/*
	 * Build a cpuset of target cpus (one per board) to
	 * be used to send the CIC update xcall.
	 */
	for (brd = 0; brd < MAX_BOARDS; brd++) {
		/*
		 * Need to target an available cpu on the target board
		 * so that we can look at the CICs on that board.
		 */
		c = board_to_ready_cpu(brd, cpu_ready_set);

		if (c == -1) {
			/*
			 * If there's no cpu on this board, no
			 * need to update the CICs.
			 */
			continue;
		}
		CPUSET_ADD(target_cpuset, c);
		target_count++;
	}

	if (CPUSET_ISNULL(target_cpuset)) {
		PR_REGS("%s: NO target cpus to update!!\n", proc);
		return (0);
	}

	RESET_CIC_HISTORY();

	/*
	 * Broadcast out the CIC update request and then
	 * sit back and wait for dinner to arrive!
	 * Let's set up the global structure all the xcall
	 * recepients will read.
	 */
	start_time = ddi_get_lbolt();
	/*
	 * Set the start time.  Make sure it's different
	 * then the previous run.
	 */
	if (start_time <= idnxf_cic_info.xf_start_time)
		start_time++;
	idnxf_cic_info.xf_start_time = start_time;

	idnxf_cic_info.xf_abus_mask = abus_mask;
	idnxf_cic_info.xf_boardset = boardset;
	idnxf_cic_info.xf_smbase = smbase;
	idnxf_cic_info.xf_smlimit = smlimit;
	idnxf_cic_info.xf_doadd = doadd;
	idnxf_cic_info.xf_count = target_count;
	idnxf_cic_info.xf_errcnt = 0;
	idnxf_cic_info.xf_errtimer = 0;
	bzero(&idnxf_cic_info.xf_errcic, sizeof (idnxf_cic_info.xf_errcic));

	/*
	 * Broadcast out the xcall to do the task.
	 */
#ifdef DEBUG
	{
		uint_t	tu32, tl32;

		tu32 = UPPER32_CPUMASK(target_cpuset);
		tl32 = LOWER32_CPUMASK(target_cpuset);
		PR_REGS("%s: (start %ld) broadcasting CIC - "
		    "%s to cpus 0x%x.%0x\n",
		    proc, start_time, doadd ? "LINK" : "UNLINK",
		    tu32, tl32);
	}

	/*
	 * Can't dump debug during cross-calls.
	 */
	o_idn_debug = idn_debug;
	idn_debug = 0;
#endif /* DEBUG */

	xc_attention(target_cpuset);

	xc_some(target_cpuset, idnxf_shmem_update_one,
	    (uint64_t)&idnxf_cic_info, (uint64_t)start_time);

	xc_dismissed(target_cpuset);

	ASSERT(idnxf_cic_info.xf_count == 0);

#ifdef DEBUG
	idn_debug = o_idn_debug;
	o_idn_debug = 0;
#endif /* DEBUG */

	PR_REGS("%s: waiting for completion of %d CIC - %s...\n",
	    proc, idnxf_cic_info.xf_count, doadd ? "LINKS" : "UNLINKS");
	PR_REGS("%s: CIC - %s have checked IN.\n",
	    proc, doadd ? "LINKS" : "UNLINKS");

	/*
	 * Modifying xf_start_time effectively disables any
	 * possible outstanding xcall's since they don't touch
	 * idnxf_cic_info unless their given start_time matches
	 * that in the idnxf_cic_info structure.
	 */
	idnxf_cic_info.xf_start_time++;

	PR_REGS("%s: xf_errcnt = %d, xf_errtimer = %d\n",
	    proc, idnxf_cic_info.xf_errcnt, idnxf_cic_info.xf_errtimer);
	DUMP_CIC_HISTORY();
	/*
	 * Should errors be fatal? (panic).
	 */
	rv = 0;
	for (c = 0; c < NCPU; c++) {
		if (!CPU_IN_SET(target_cpuset, c))
			continue;
		brd = CPUID_TO_BOARDID(c);

		for (bus = 0; bus < MAX_ABUSES; bus++) {

			if (!(abus_mask & (1 << bus)))
				continue;

			switch (idnxf_cic_info.xf_errcic[brd][bus]) {
			case IDNCIC_UNKNOWN:
				/*
				 * Unknown is only an error if the
				 * timer expired.
				 */
				if (!idnxf_cic_info.xf_errtimer)
					break;
				cmn_err(CE_WARN,
				    "IDN: 509: CPU %d never responded "
				    "to CIC update", c);
				/*FALLTHROUGH*/

			case IDNCIC_ERR:
				cmn_err(CE_WARN,
				    "IDN: 510: failed write-smregs "
				    "(bd=%d, bs=%d, sm(bar=0x%x, "
				    "lar=0x%x))",
				    brd, bus, smbase, smlimit);
				rv++;
				break;

			case IDNCIC_BUSY:
				cmn_err(CE_WARN, "IDN: 511: update-one "
				    "(cpu=%d, bd=%d) time conflict",
				    c, brd);
				/*
				 * Should never occur.  Not fatal,
				 * just continue.
				 */
				break;

			default:
				PR_REGS("%s: board %d, bus %d "
				    "(bar=0x%x,lar=0x%x) - update OK\n",
				    proc, brd, bus, smbase, smlimit);
				break;
			}
		}
	}

	return (rv ? -1 : 0);
}

/*
 * Add the respective boardset/base/limit/mcadr's to the local
 * domain's hardware configuration with respect to the SMR.
 *
 * is_master	Indicates remote domain is a master.
 */
int
idnxf_shmem_add(int is_master, boardset_t boardset, pfn_t pfnbase,
    pfn_t pfnlimit, uint_t *mcadr)
{
	int		rv = 0;
	register int	brd, rbrd;
	register boardset_t	localboardset;
	uint_t		madr;
	uint_t		smbase, smlimit;
	pda_handle_t	ph;
	procname_t	proc = "idnxf_shmem_add";


	localboardset = idn_domain[idn.localid].dhw.dh_boardset;

	ASSERT(localboardset && boardset && ((localboardset & boardset) == 0));
	ASSERT(is_master ? (pfnbase && pfnlimit && mcadr) : 1);

	if (pfnbase != PFN_INVALID) {
		smbase  = (uint_t)PFN_TO_SMADDR(pfnbase);
		smlimit = (uint_t)PFN_TO_SMADDR(pfnlimit);
	} else {
		smbase = smlimit = (uint_t)-1;
	}
	PR_REGS("%s: is_master=%d, boardset=0x%x, smbase=0x%x, smlimit=%x\n",
	    proc, is_master, boardset, smbase, smlimit);

	/*
	 * Need to serialize hardware access so we don't have multiple
	 * threads attempting to access hardware regs simulataneously.
	 * This should not be a significant performance penalty since
	 * the hardware is only touched when domains are linking or
	 * unlinking.
	 */
	mutex_enter(&idn_xf_mutex);

	/*
	 * Map in the post2obp structure so we can find
	 * bus config information.
	 */
	ph = pda_open();
	if (ph == (pda_handle_t)NULL) {
		cmn_err(CE_WARN,
		    "IDN: 507: failed to map-in post2obp structure");
		rv = -1;
		goto done;

	} else if (!pda_is_valid(ph)) {
		cmn_err(CE_WARN, "IDN: 508: post2obp checksum invalid");
		rv = -1;
		goto done;
	}
	/*
	 * Take a checkpoint in bbsram for diagnostic purposes.
	 */
	CHECKPOINT_OPENED(IDNSB_CHKPT_SMR, boardset, 1);

	rv = idnxf_shmem_update_all(ph, boardset, smbase, smlimit, 1);

	if (rv || (is_master == 0))
		goto done;

	/*
	 * If this is a slave (i.e. remote domain is_master),
	 * then we need to deprogram our PCs.
	 */
	PR_REGS("%s: updating PC regs (lboardset=0x%x, rboardset=0x%x)\n",
	    proc, localboardset, boardset);

	for (brd = 0; brd < MAX_BOARDS; brd++) {

		if (!BOARD_IN_SET(localboardset, brd))
			continue;
		/*
		 * If this is a slave (i.e. remote domain is_master),
		 * then we need to program our PCs.
		 */
		for (rbrd = 0; rbrd < MAX_BOARDS; rbrd++) {

			if ((madr = mcadr[rbrd]) == 0)
				continue;

			ASSERT(BOARD_IN_SET(boardset, rbrd));
			/*
			 * Write the MC adr for the respective
			 * remote board (rbrd) into the PCs of
			 * the given local board (brd).
			 */
			if (pc_write_madr(ph, brd, rbrd, madr) < 0) {
				cmn_err(CE_WARN,
				    "IDN: 512: failed [add] write-madr "
				    "(bd=%d, rbd=%d, madr=0x%x)",
				    brd, rbrd, madr);
				rv = -1;
				goto done;
			}
		}
	}

done:
	if (ph)
		pda_close(ph);

	mutex_exit(&idn_xf_mutex);
	/*
	 * XXX
	 *
	 * Failure here is fatal.  Disable IDN?
	 * NOn-zero return value will at least prevent
	 * linkage with domain - probably sufficient.
	 */
	return (rv);
}

/*
 * Remove the respective boardset from the local domain's
 * hardware configuration with respect to the SMR.
 *
 * is_master	Indicates remote domain is a master.
 */
int
idnxf_shmem_sub(int is_master, boardset_t boardset)
{
	int		rv = 0;
	register int	brd, rbrd;
	register boardset_t	localboardset;
	pda_handle_t	ph;
	procname_t	proc = "idnxf_shmem_sub";

	localboardset = idn_domain[idn.localid].dhw.dh_boardset;

	ASSERT(localboardset && boardset && ((localboardset & boardset) == 0));

	PR_REGS("%s: is_master=%d, boardset=0x%x\n",
	    proc, is_master, boardset);

	/*
	 * Need to serialize hardware access so we don't have multiple
	 * threads attempting to access hardware regs simulataneously.
	 * This should not be a significant performance penalty since
	 * the hardware is only touched when domains are linking or
	 * unlinking.
	 */
	mutex_enter(&idn_xf_mutex);

	/*
	 * Map in the post2obp structure so we can find
	 * bus config information.
	 */
	ph = pda_open();
	if (ph == (pda_handle_t)NULL) {
		cmn_err(CE_WARN,
		    "IDN: 507: failed to map-in post2obp structure");
		rv = -1;
		goto done;

	} else if (!pda_is_valid(ph)) {
		cmn_err(CE_WARN, "IDN: 508: post2obp checksum invalid");
		rv = -1;
		goto done;
	}
	/*
	 * Take a checkpoint in bbsram for diagnostic purposes.
	 */
	CHECKPOINT_CLOSED(IDNSB_CHKPT_SMR, boardset, 2);

	rv = idnxf_shmem_update_all(ph, boardset, (uint_t)-1, (uint_t)-1, 0);

	if (rv || (is_master == 0))
		goto done;

	/*
	 * If this is a slave (i.e. remote domain is_master),
	 * then we need to deprogram our PCs.
	 */
	PR_REGS("%s: reseting PC regs (lboardset=0x%x, rboardset=0x%x)\n",
	    proc, localboardset, boardset);

	for (brd = 0; brd < MAX_BOARDS; brd++) {

		if (!BOARD_IN_SET(localboardset, brd))
			continue;

		for (rbrd = 0; rbrd < MAX_BOARDS; rbrd++) {

			if (!BOARD_IN_SET(boardset, rbrd))
				continue;
			/*
			 * Clear the MC adr for the respective
			 * remote board (rbrd) into the PCs of
			 * the given local board (brd).
			 */
			if (pc_write_madr(ph, brd, rbrd, 0) < 0) {
				cmn_err(CE_WARN,
				    "IDN: 512: failed [del] write-madr "
				    "(bd=%d, rbd=%d, madr=0x%x)",
				    brd, rbrd, 0);
				rv = -1;
				goto done;
			}
		}
	}

done:
	if (ph)
		pda_close(ph);
	mutex_exit(&idn_xf_mutex);

	return (rv);
}

/*
 * We cannot cross-trap cpu_flush_ecache since it references
 * %g7 via CPU.  It's possible that %g7 may not be set up
 * when the trap comes in, and could thus cause a crash.
 * Well...at least that's what has been happening when I
 * tried x-calls within an xc_attention (KMISS) panic.
 * Instead we use cross-calls.  However, since we can't
 * xc_attention around a cross-call, we have not guaranteed
 * way of knowing the operation succeeded.  To synchronize
 * this flush operation across cpus, we use a semaphore
 * which is V'd by the receiving cpus and P'd by the caller
 * initiating the all-cpus flush.
 */
/*ARGSUSED0*/
void
idn_flush_ecache(uint64_t arg1, uint64_t arg2)
{
	extern void	cpu_flush_ecache(void);

	cpu_flush_ecache();
	/*
	 * Paranoia...Give things a chance to drain.
	 */
	drv_usecwait(500000);	/* 500 msec */
}
/*
 * Flush the ecache's of all the cpus within this domain of
 * any possible SMR references.
 * This logic is borrowed from ecc.c:cpu_flush_ecache().
 */
void
idnxf_flushall_ecache()
{
	cpuset_t	local_cpuset;
	procname_t	proc = "idnxf_flushall_ecache";


	PR_XF("%s: flushing ecache (cpu_ready_set = 0x%x.%x)\n", proc,
	    UPPER32_CPUMASK(cpu_ready_set), LOWER32_CPUMASK(cpu_ready_set));

	CHECKPOINT_CACHE_CLEAR_DEBUG(1);
	CHECKPOINT_CACHE_STEP_DEBUG(0x1, 2);

	local_cpuset = cpu_ready_set;

	xc_attention(local_cpuset);

	/*
	 * We tell each cpu to do a flush and then we hit
	 * a semaphore to synchronize with all of them
	 * to guarantee they have completed the flush before
	 * we continue on.  We have to do this type of
	 * sychronization since we can't xc_attention around
	 * a cross-call.
	 */
	CHECKPOINT_CACHE_STEP_DEBUG(0x2, 3);

	xc_all(idn_flush_ecache, 0, 0);

	CHECKPOINT_CACHE_STEP_DEBUG(0x4, 4);

	xc_dismissed(local_cpuset);

	CHECKPOINT_CACHE_STEP_DEBUG(0x8, 5);
}

/*
 * --------------------------------------------------
 */
static int
verify_smregs(int brd, int bus, boardset_t smmask, uint_t smbase, uint_t
    smlimit)
{
	int		rv = 0;
	uint_t		smreg;

	if (smmask != (boardset_t)-1) {
		smreg = (uint_t)cic_read_sm_mask(brd, bus);
		if (smreg != (uint_t)smmask) {
			cmn_err(CE_WARN,
			    "IDN: 513: sm-mask error "
			    "(expected = 0x%x, actual = 0x%x)",
			    (uint_t)smmask, smreg);
			rv++;
		}
	}

	if (smbase != (uint_t)-1) {
		smreg = cic_read_sm_bar(brd, bus);
		if (smreg != smbase) {
			cmn_err(CE_WARN,
			    "IDN: 514: sm-base error "
			    "(expected = 0x%x, actual = 0x%x)",
			    smbase, smreg);
			rv++;
		}
	}

	if (smlimit != (uint_t)-1) {
		smreg = cic_read_sm_lar(brd, bus);
		if (smreg != smlimit) {
			cmn_err(CE_WARN,
			    "IDN: 515: sm-limit error "
			    "(expected = 0x%x, actual = 0x%x)",
			    smlimit, smreg);
			rv++;
		}
	}

	return (rv ? -1 : 0);
}

/*
 * -------------------------------------------------------------
 */
int
idn_cpu_per_board(pda_handle_t ph, cpuset_t cset, struct hwconfig *hwp)
{
	int		b, err = 0;
	boardset_t	bset, cpu_bset;
	board_desc_t	*lbp;

	if (!idn_check_cpu_per_board)
		return (1);

	bset = hwp->dh_boardset;
	CPUSET_TO_BOARDSET(cset, cpu_bset);

	/*
	 * Every board has at least one cpu, we're happy.
	 */
	if (cpu_bset == bset)
		return (1);

	/*
	 * Well, not all boards had cpus.  That's okay so
	 * long as they don't have memory also.
	 * Get rid of the boards that have a cpu.
	 */
	bset &= ~cpu_bset;
	/*
	 * None of the remaining boards in the set shold have mem.
	 */
	err = 0;

	/*
	 * A NULL post2obp pointer indicates we're checking
	 * the config of a remote domain.  Since we can't
	 * look at the post2obp of the remote domain, we'll
	 * have to trust what it passed us in its config.
	 */
	if (ph && !pda_is_valid(ph)) {
		cmn_err(CE_WARN, "IDN: 508: post2obp checksum invalid");
		return (0);
	}

	for (b = 0; b < MAX_BOARDS; b++) {
		if (!BOARD_IN_SET(bset, b))
			continue;

		lbp = ph ? pda_get_board_info(ph, b) : NULL;

		if ((lbp &&
		    (BDA_NBL(lbp->bda_board, BDA_MC_NBL) == BDAN_GOOD)) ||
		    (!lbp && hwp->dh_mcadr[b])) {
			err++;
			cmn_err(CE_WARN,
			    "IDN: 516: (%s) board %d has memory, "
			    "but no CPUs - CPU per memory board REQUIRED",
			    ph ? "local" : "remote", b);
		}
	}

	return (err ? 0 : 1);
}
