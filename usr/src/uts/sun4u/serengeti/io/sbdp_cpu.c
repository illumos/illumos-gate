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

/*
 * CPU management for serengeti DR
 *
 * There are three states a CPU can be in:
 *
 *	disconnected:		In reset
 *	connect,unconfigured:	Idling in OBP's idle loop
 *	configured:		Running Solaris
 *
 * State transitions:
 *
 *                connect              configure
 *              ------------>         ------------>
 * disconnected              connected             configured
 *                          unconfigured
 *              <-----------         <-------------
 *                disconnect           unconfigure
 *
 * Firmware involvements
 *
 *              start_cpu(SC)
 *      prom_serengeti_wakeupcpu(OBP)
 *              ------------>         ------------------------->
 * disconnected              connected                         configured
 *                          unconfigured
 *              <-----------          <-------------------------
 *      prom_serengeti_cpu_off(OBP)  prom_serengeti_cpu_off(OBP)
 *               stop_cpu(SC)        prom_serengeti_wakeupcpu(OBP)
 *
 * SIR (Software Initiated Reset) is used to unconfigure a CPU.
 * After the CPU has completed flushing the caches, it issues an
 * sir instruction to put itself through POST.  POST detects that
 * it is an SIR, and re-enters OBP as a slave.  When the operation
 * completes successfully, the CPU will be idling in OBP.
 */

#include <sys/obpdefs.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/membar.h>
#include <sys/x_call.h>
#include <sys/machsystm.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/pte.h>
#include <vm/hat_sfmmu.h>
#include <sys/promif.h>
#include <sys/note.h>
#include <sys/vmsystm.h>
#include <vm/seg_kmem.h>

#include <sys/sbd_ioctl.h>
#include <sys/sbd.h>
#include <sys/sbdp_priv.h>
#include <sys/sbdp_mem.h>
#include <sys/sbdp_error.h>
#include <sys/sgsbbc_iosram.h>
#include <sys/prom_plat.h>
#include <sys/cheetahregs.h>

uint64_t	*sbdp_valp;
extern uint64_t	va_to_pa(void *);
static int	sbdp_cpu_ntries = 50000;
static int	sbdp_cpu_delay = 100;
void		sbdp_get_cpu_sram_addr(uint64_t, uint64_t);
static int	cpusram_map(caddr_t *, pgcnt_t *);
static void	cpusram_unmap(caddr_t *, pgcnt_t);
extern int	prom_serengeti_wakeupcpu(pnode_t);
extern int	prom_serengeti_cpu_off(pnode_t);
extern sbdp_wnode_t *sbdp_get_wnodep(int);
extern caddr_t	sbdp_shutdown_va;
static int	sbdp_prom_get_cpu(void *arg, int changed);
static void	sbdp_cpu_shutdown_self(void);

int
sbdp_disconnect_cpu(sbdp_handle_t *hp, dev_info_t *dip, processorid_t cpuid)
{
	pnode_t		nodeid;
	int		bd, wnode;
	sbdp_wnode_t	*wnodep;
	sbdp_bd_t	*bdp = NULL;
	int		rv = 0;
	processorid_t	cpu = cpuid;
	processorid_t	portid;
	static fn_t	f = "sbdp_disconnect_cpu";

	SBDP_DBG_FUNC("%s\n", f);

	nodeid = ddi_get_nodeid(dip);

	/*
	 * Get board number and node number
	 * The check for determining if nodeid is valid is done inside
	 * sbdp_get_bd_and_wnode_num.
	 */
	if (SBDP_INJECT_ERROR(f, 0) ||
	    sbdp_get_bd_and_wnode_num(nodeid, &bd, &wnode) != 0) {

		rv = -1;
		goto out;
	}

	/*
	 * Grab the lock to prevent status threads from accessing
	 * registers on the CPU when it is being put into reset.
	 */
	wnodep = sbdp_get_wnodep(wnode);
	bdp = &wnodep->bds[bd];
	ASSERT(bdp);
	mutex_enter(&bdp->bd_mutex);

	/*
	 * Mark the CPU in reset.  This should be done before calling
	 * the SC because we won't know at which stage it failed if
	 * the SC call returns failure.
	 */
	sbdp_cpu_in_reset(wnode, bd, SG_CPUID_TO_CPU_UNIT(cpuid), 1);

	/*
	 * Ask OBP to mark the CPU as in POST
	 */
	if (SBDP_INJECT_ERROR(f, 1) || prom_serengeti_cpu_off(nodeid) != 0) {

		rv = -1;
		goto out;
	}

	/*
	 * Ask the SC to put the CPU into reset. If the first
	 * core is not present, the stop CPU interface needs
	 * to be called with the portid rather than the cpuid.
	 */
	portid = SG_CPUID_TO_PORTID(cpuid);
	if (!SBDP_IS_CPU_PRESENT(bdp, SG_CPUID_TO_CPU_UNIT(portid))) {
		cpu = portid;
	}

	if (SBDP_INJECT_ERROR(f, 2) || sbdp_stop_cpu(cpu) != 0) {

		rv = -1;
		goto out;
	}

out:
	if (bdp != NULL) {
		mutex_exit(&bdp->bd_mutex);
	}

	if (rv != 0) {
		sbdp_set_err(hp->h_err, ESGT_STOPCPU, NULL);
	}

	return (rv);
}

int
sbdp_connect_cpu(sbdp_handle_t *hp, dev_info_t *dip, processorid_t cpuid)
{
	pnode_t		nodeid;
	sbd_error_t	*sep;
	int		i;
	int		bd, wnode;
	int		rv = 0;
	static fn_t	f = "sbdp_connect_cpu";

	SBDP_DBG_FUNC("%s\n", f);

	sep = hp->h_err;

	nodeid = ddi_get_nodeid(dip);

	/*
	 * The check for determining if nodeid is valid is done inside
	 * sbdp_get_bd_and_wnode_num.
	 */
	if (SBDP_INJECT_ERROR(f, 0) ||
	    sbdp_get_bd_and_wnode_num(nodeid, &bd, &wnode) != 0) {

		rv = -1;
		goto out;
	}

	/*
	 * Ask the SC to bring the CPU out of reset.
	 * At this point, the sb_dev_present bit is not set for the CPU.
	 * From sbd point of view the CPU is not present yet.  No
	 * status threads will try to read registers off the CPU.
	 * Since we are already holding sb_mutex, it is not necessary
	 * to grab the board mutex when checking and setting the
	 * cpus_in_reset bit.
	 */
	if (sbdp_is_cpu_in_reset(wnode, bd, SG_CPUID_TO_CPU_UNIT(cpuid))) {

		sbdp_wnode_t	*wnodep;
		sbdp_bd_t	*bdp = NULL;
		processorid_t	cpu = cpuid;
		processorid_t	portid;

		wnodep = sbdp_get_wnodep(wnode);
		bdp = &wnodep->bds[bd];
		ASSERT(bdp);

		/*
		 * If the first core is not present, the start CPU
		 * interface needs to be called with the portid rather
		 * than the cpuid.
		 */
		portid = SG_CPUID_TO_PORTID(cpuid);
		if (!SBDP_IS_CPU_PRESENT(bdp, SG_CPUID_TO_CPU_UNIT(portid))) {
			cpu = portid;
		}

		if (SBDP_INJECT_ERROR(f, 1) || sbdp_start_cpu(cpu) != 0) {

			rv = -1;
			goto out;
		}

		if (SBDP_INJECT_ERROR(f, 2) ||
		    prom_serengeti_wakeupcpu(nodeid) != 0) {

			rv = -1;
			goto out;
		}
	}

	/*
	 * Mark the CPU out of reset.
	 */
	sbdp_cpu_in_reset(wnode, bd, SG_CPUID_TO_CPU_UNIT(cpuid), 0);

	/*
	 * Refresh the bd info
	 * we need to wait until all cpus are out of reset
	 */
	for (i = 0; i < SG_MAX_CPUS_PER_BD; i++)
		if (sbdp_is_cpu_present(wnode, bd, i) &&
		    sbdp_is_cpu_in_reset(wnode, bd, i) == 1) {
			break;
		}

	if (i == SG_MAX_CPUS_PER_BD) {
		/*
		 * All cpus are out of reset so it is safe to
		 * update the bd info
		 */
		sbdp_add_new_bd_info(wnode, bd);
	}

out:
	if (rv != 0)
		sbdp_set_err(sep, ESGT_WAKEUPCPU, NULL);

	return (rv);
}

int
sbdp_cpu_poweron(struct cpu *cp)
{
	int		cpuid;
	int		ntries;
	pnode_t		nodeid;
	extern void	restart_other_cpu(int);
	static fn_t	f = "sbdp_cpu_poweron";

	SBDP_DBG_FUNC("%s\n", f);

	ASSERT(MUTEX_HELD(&cpu_lock));

	ntries = sbdp_cpu_ntries;
	cpuid = cp->cpu_id;

	nodeid = cpunodes[cpuid].nodeid;
	ASSERT(nodeid != (pnode_t)0);

	/*
	 * This is a safe guard in case the CPU has taken a trap
	 * and idling in POST.
	 */
	if (SBDP_INJECT_ERROR(f, 0) ||
	    prom_serengeti_wakeupcpu(nodeid) != 0) {

		return (EBUSY);
	}

	cp->cpu_flags &= ~CPU_POWEROFF;

	/*
	 * NOTE: restart_other_cpu pauses cpus during the
	 *	slave cpu start.  This helps to quiesce the
	 *	bus traffic a bit which makes the tick sync
	 *	routine in the prom more robust.
	 */
	SBDP_DBG_CPU("%s: COLD START for cpu (%d)\n", f, cpuid);

	restart_other_cpu(cpuid);

	SBDP_DBG_CPU("after restarting other cpus\n");

	/*
	 * Wait for the cpu to reach its idle thread before
	 * we zap it with a request to blow away the mappings
	 * it (might) have for the sbdp_shutdown_asm code
	 * it may have executed on unconfigure.
	 */
	while ((cp->cpu_thread != cp->cpu_idle_thread) && (ntries > 0)) {
		DELAY(sbdp_cpu_delay);
		ntries--;
	}

	SBDP_DBG_CPU("%s: waited %d out of %d loops for cpu %d\n",
	    f, sbdp_cpu_ntries - ntries, sbdp_cpu_ntries, cpuid);

	return (0);
}


#define	SBDP_CPU_SRAM_ADDR	0x7fff0900000ull
#define	SBDP_CPU_SRAM_SIZE	0x20000ull

static const char cpyren_key[] = "COPYREN";

static uint64_t bbsram_pa;
static uint_t bbsram_size;

typedef struct {
	caddr_t		vaddr;
	pgcnt_t		npages;
	uint64_t	*pa;
	uint_t		*size;
} sbdp_cpu_sram_map_t;

int
sbdp_cpu_poweroff(struct cpu *cp)
{
	processorid_t	cpuid;
	pnode_t		nodeid;
	sbdp_cpu_sram_map_t	map;
	static fn_t	f = "sbdp_cpu_poweroff";

	SBDP_DBG_FUNC("%s\n", f);

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Capture all CPUs (except for detaching proc) to prevent
	 * crosscalls to the detaching proc until it has cleared its
	 * bit in cpu_ready_set.
	 */
	cpuid = cp->cpu_id;

	nodeid = cpunodes[cpuid].nodeid;
	ASSERT(nodeid != (pnode_t)0);

	*sbdp_valp = 0ull;
	/*
	 * Do the cpu sram mapping now.  This avoids problems with
	 * mutexes and high PILS
	 */
	if (SBDP_INJECT_ERROR(f, 0) ||
	    cpusram_map(&map.vaddr, &map.npages) != DDI_SUCCESS) {
		return (EBUSY);
	}

	map.pa = &bbsram_pa;
	map.size = &bbsram_size;

	/*
	 * Do a cross call to the cpu so it obtains the base address
	 */
	xc_one(cpuid, sbdp_get_cpu_sram_addr, (uint64_t)&map,
	    (uint64_t)NULL);

	cpusram_unmap(&map.vaddr, map.npages);

	if (SBDP_INJECT_ERROR(f, 1) || bbsram_size == 0) {
		cmn_err(CE_WARN, "cpu%d: Key \"%s\" missing from CPU SRAM TOC",
		    cpuid, cpyren_key);
		return (EBUSY);
	}

	if ((bbsram_pa & MMU_PAGEOFFSET) != 0) {
		cmn_err(CE_WARN, "cpu%d: CPU SRAM key \"%s\" not page aligned, "
		    "offset = 0x%lx", cpuid, cpyren_key,
		    (bbsram_pa - (uint64_t)SBDP_CPU_SRAM_ADDR));
		return (EBUSY);
	}

	if (bbsram_size < MMU_PAGESIZE) {
		cmn_err(CE_WARN, "cpu%d: CPU SRAM key \"%s\" too small, "
		    "size = 0x%x", cpuid, cpyren_key, bbsram_size);
		return (EBUSY);
	}

	/*
	 * Capture all CPUs (except for detaching proc) to prevent
	 * crosscalls to the detaching proc until it has cleared its
	 * bit in cpu_ready_set.
	 *
	 * The CPU's remain paused and the prom_mutex is known to be free.
	 * This prevents the x-trap victim from blocking when doing prom
	 * IEEE-1275 calls at a high PIL level.
	 */

	promsafe_pause_cpus();

	/*
	 * Quiesce interrupts on the target CPU. We do this by setting
	 * the CPU 'not ready'- (i.e. removing the CPU from cpu_ready_set) to
	 * prevent it from receiving cross calls and cross traps.
	 * This prevents the processor from receiving any new soft interrupts.
	 */

	mp_cpu_quiesce(cp);

	/* tell the prom the cpu is going away */
	if (SBDP_INJECT_ERROR(f, 2) || prom_serengeti_cpu_off(nodeid) != 0)
		return (EBUSY);

	/*
	 * An sir instruction is issued at the end of the shutdown
	 * routine to make the CPU go through POST and re-enter OBP.
	 */
	xt_one_unchecked(cp->cpu_id, (xcfunc_t *)idle_stop_xcall,
	    (uint64_t)sbdp_cpu_shutdown_self, 0);

	*sbdp_valp = 3ull;

	start_cpus();

	/*
	 * Wait until we reach the OBP idle loop or time out.
	 * prom_serengeti_wakeupcpu waits for up to 60 seconds for the
	 * CPU to reach OBP idle loop.
	 */
	if (SBDP_INJECT_ERROR(f, 3) ||
	    prom_serengeti_wakeupcpu(nodeid) != 0) {

		/*
		 * If it fails here, we still consider the unconfigure
		 * operation as successful.
		 */
		cmn_err(CE_WARN, "cpu%d: CPU failed to enter OBP idle loop.\n",
		    cpuid);
	}

	ASSERT(!(CPU_IN_SET(cpu_ready_set, cpuid)));

	bbsram_pa = 0;
	bbsram_size = 0;

	return (0);
}

processorid_t
sbdp_get_cpuid(sbdp_handle_t *hp, dev_info_t *dip)
{
	int		cpuid;
	char		type[OBP_MAXPROPNAME];
	pnode_t		nodeid;
	sbd_error_t	*sep;
	static fn_t	f = "sbdp_get_cpuid";

	SBDP_DBG_FUNC("%s\n", f);

	nodeid = ddi_get_nodeid(dip);
	if (sbdp_is_node_bad(nodeid))
		return (-1);

	sep = hp->h_err;

	if (prom_getproplen(nodeid, "device_type") < OBP_MAXPROPNAME)
		(void) prom_getprop(nodeid, "device_type", (caddr_t)type);
	else {
		sbdp_set_err(sep, ESGT_NO_DEV_TYPE, NULL);
		return (-1);
	}

	if (strcmp(type, "cpu") != 0) {
		sbdp_set_err(sep, ESGT_NOT_CPUTYPE, NULL);
		return (-1);
	}

	/*
	 * Check to see if property "cpuid" exists first.
	 * If not, check for "portid".
	 */
	if (prom_getprop(nodeid, "cpuid", (caddr_t)&cpuid) == -1)
		if (prom_getprop(nodeid, "portid", (caddr_t)&cpuid) == -1) {

			return (-1);
	}

	return ((processorid_t)cpuid & SG_CPU_ID_MASK);
}

int
sbdp_cpu_get_impl(sbdp_handle_t *hp, dev_info_t *dip)
{
	int		impl;
	char		type[OBP_MAXPROPNAME];
	pnode_t		nodeid;
	sbd_error_t	*sep;
	static fn_t	f = "sbdp_cpu_get_impl";

	SBDP_DBG_FUNC("%s\n", f);

	nodeid = ddi_get_nodeid(dip);
	if (sbdp_is_node_bad(nodeid))
		return (-1);

	sep = hp->h_err;

	if (prom_getproplen(nodeid, "device_type") < OBP_MAXPROPNAME)
		(void) prom_getprop(nodeid, "device_type", (caddr_t)type);
	else {
		sbdp_set_err(sep, ESGT_NO_DEV_TYPE, NULL);
		return (-1);
	}

	if (strcmp(type, "cpu") != 0) {
		sbdp_set_err(sep, ESGT_NOT_CPUTYPE, NULL);
		return (-1);
	}

	/*
	 * Get the implementation# property.
	 */
	if (prom_getprop(nodeid, "implementation#", (caddr_t)&impl) == -1)
		return (-1);

	return (impl);
}

struct sbdp_prom_get_node_args {
	pnode_t node;		/* current node */
	processorid_t portid;	/* portid we are looking for */
	pnode_t result_node;	/* node found with the above portid */
};

pnode_t
sbdp_find_nearby_cpu_by_portid(pnode_t nodeid, processorid_t portid)
{
	struct sbdp_prom_get_node_args arg;
	static fn_t	f = "sbdp_find_nearby_cpu_by_portid";

	SBDP_DBG_FUNC("%s\n", f);

	arg.node = nodeid;
	arg.portid = portid;
	(void) prom_tree_access(sbdp_prom_get_cpu, &arg, NULL);

	return (arg.result_node);
}

/*ARGSUSED*/
static int
sbdp_prom_get_cpu(void *arg, int changed)
{
	int	portid;
	pnode_t	parent, cur_node;
	struct sbdp_prom_get_node_args *argp = arg;
	static fn_t	f = "sbdp_prom_get_cpu";

	SBDP_DBG_FUNC("%s\n", f);

	parent = prom_parentnode(argp->node);

	for (cur_node = prom_childnode(parent); cur_node != OBP_NONODE;
	    cur_node = prom_nextnode(cur_node)) {

		if (prom_getprop(cur_node, OBP_PORTID, (caddr_t)&portid) < 0)
			continue;

		if ((portid == argp->portid) && (cur_node != argp->node))
			break;
	}

	argp->result_node = cur_node;

	return (0);
}


/*
 * A detaching CPU is xcalled with an xtrap to sbdp_cpu_stop_self() after
 * it has been offlined. The function of this routine is to get the cpu
 * spinning in a safe place. The requirement is that the system will not
 * reference anything on the detaching board (memory and i/o is detached
 * elsewhere) and that the CPU not reference anything on any other board
 * in the system.  This isolation is required during and after the writes
 * to the domain masks to remove the board from the domain.
 *
 * To accomplish this isolation the following is done:
 *	0) Map the CPUSRAM to obtain the correct address in SRAM
 *      1) Create a locked mapping to a location in CPU SRAM where
 *      the cpu will execute.
 *      2) Copy the target function (sbdp_shutdown_asm) in which
 *      the cpu will execute into CPU SRAM.
 *      3) Jump into function with CPU SRAM.
 *      Function will:
 *      3.1) Flush its Ecache (displacement).
 *      3.2) Flush its Dcache with HW mechanism.
 *      3.3) Flush its Icache with HW mechanism.
 *      3.4) Flush all valid and _unlocked_ D-TLB entries.
 *      3.5) Flush all valid and _unlocked_ I-TLB entries.
 *      4) Jump into a tight loop.
 */

static void
sbdp_cpu_stop_self(uint64_t pa)
{
	cpu_t		*cp = CPU;
	int		cpuid = cp->cpu_id;
	tte_t		tte;
	volatile uint_t	*src, *dst;
	size_t		funclen;
	sbdp_shutdown_t	sht;
	uint_t		bbsram_pfn;
	uint64_t	bbsram_addr;
	void		(*bbsram_func)(sbdp_shutdown_t *);
	extern void	sbdp_shutdown_asm(sbdp_shutdown_t *);
	extern void	sbdp_shutdown_asm_end(void);

	funclen = (uintptr_t)sbdp_shutdown_asm_end -
	    (uintptr_t)sbdp_shutdown_asm;
	ASSERT(funclen <= MMU_PAGESIZE);
	ASSERT(bbsram_pa != 0);
	ASSERT((bbsram_pa & MMU_PAGEOFFSET) == 0);
	ASSERT(bbsram_size >= MMU_PAGESIZE);

	stdphys(pa, 3);
	bbsram_pfn = (uint_t)(bbsram_pa >> MMU_PAGESHIFT);

	bbsram_addr = (uint64_t)sbdp_shutdown_va;
	sht.estack = bbsram_addr + MMU_PAGESIZE;
	sht.flushaddr = ecache_flushaddr;

	tte.tte_inthi = TTE_VALID_INT | TTE_SZ_INT(TTE8K) |
	    TTE_PFN_INTHI(bbsram_pfn);
	tte.tte_intlo = TTE_PFN_INTLO(bbsram_pfn) |
	    TTE_HWWR_INT | TTE_PRIV_INT | TTE_LCK_INT;
	sfmmu_dtlb_ld_kva(sbdp_shutdown_va, &tte); /* load dtlb */
	sfmmu_itlb_ld_kva(sbdp_shutdown_va, &tte); /* load itlb */

	for (src = (uint_t *)sbdp_shutdown_asm, dst = (uint_t *)bbsram_addr;
	    src < (uint_t *)sbdp_shutdown_asm_end; src++, dst++)
	*dst = *src;

	bbsram_func = (void (*)())bbsram_addr;
	sht.size = (uint32_t)cpunodes[cpuid].ecache_size << 1;
	sht.linesize = (uint32_t)cpunodes[cpuid].ecache_linesize;
	sht.physaddr = pa;

	/*
	 * Signal to sbdp_cpu_poweroff() that we're just
	 * about done.
	 */
	cp->cpu_m.in_prom = 1;

	stdphys(pa, 4);
	(*bbsram_func)(&sht);
}

/* ARGSUSED */
void
sbdp_get_cpu_sram_addr(uint64_t arg1, uint64_t arg2)
{
	uint64_t	*pap;
	uint_t		*sizep;
	struct iosram_toc *tocp;
	uint_t		offset;
	uint_t		size;
	sbdp_cpu_sram_map_t *map;
	int		i;
	fn_t		f = "sbdp_get_cpu_sram_addr";

	SBDP_DBG_FUNC("%s\n", f);

	map = (sbdp_cpu_sram_map_t *)arg1;
	tocp = (struct iosram_toc *)map->vaddr;
	pap = map->pa;
	sizep = map->size;

	for (i = 0; i < tocp->iosram_tagno; i++) {
		if (strcmp(tocp->iosram_keys[i].key, cpyren_key) == 0)
			break;
	}
	if (i == tocp->iosram_tagno) {
		*pap = 0;
		*sizep = 0;
		return;
	}
	offset = tocp->iosram_keys[i].offset;
	size = tocp->iosram_keys[i].size;

	/*
	 * The address we want is the begining of cpusram + offset
	 */
	*pap = SBDP_CPU_SRAM_ADDR + offset;

	*sizep = size;
}

static int
cpusram_map(caddr_t *vaddrp, pgcnt_t *npp)
{
	uint_t		pgoffset;
	pgcnt_t		npages;
	pfn_t		pfn;
	uint64_t	base;
	caddr_t		kaddr;
	uint_t		mapping_attr;

	base = (uint64_t)SBDP_CPU_SRAM_ADDR & (~MMU_PAGEOFFSET);
	pfn = mmu_btop(base);

	/*
	 * Do a quick sanity check to make sure we are in I/O space.
	 */
	if (pf_is_memory(pfn))
		return (DDI_FAILURE);

	pgoffset = (ulong_t)SBDP_CPU_SRAM_ADDR & MMU_PAGEOFFSET;
	npages = mmu_btopr(SBDP_CPU_SRAM_SIZE + pgoffset);

	kaddr = vmem_alloc(heap_arena, ptob(npages), VM_NOSLEEP);
	if (kaddr == NULL)
		return (DDI_ME_NORESOURCES);

	mapping_attr = PROT_READ;
	/*
	 * Now map in the pages we've allocated...
	 */
	hat_devload(kas.a_hat, kaddr, ptob(npages), pfn, mapping_attr,
	    HAT_LOAD_LOCK);

	*vaddrp = kaddr + pgoffset;
	*npp = npages;

	return (DDI_SUCCESS);
}

static void
cpusram_unmap(caddr_t *vaddrp, pgcnt_t npages)
{
	uint_t  pgoffset;
	caddr_t base;
	caddr_t addr = *vaddrp;


	pgoffset = (ulong_t)SBDP_CPU_SRAM_ADDR & MMU_PAGEOFFSET;
	base = addr - pgoffset;
	hat_unload(kas.a_hat, base, ptob(npages), HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, base, ptob(npages));

	*vaddrp = 0;
}


static void
sbdp_cpu_shutdown_self(void)
{
	cpu_t		*cp = CPU;
	int		cpuid = cp->cpu_id;
	extern void	flush_windows(void);
	uint64_t	pa = va_to_pa((void *)sbdp_valp);

	stdphys(pa, 8);
	flush_windows();

	(void) spl8();

	stdphys(pa, 6);

	ASSERT(cp->cpu_intr_actv == 0);
	ASSERT(cp->cpu_thread == cp->cpu_idle_thread ||
	    cp->cpu_thread == cp->cpu_startup_thread);

	cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;

	CPU_SIGNATURE(OS_SIG, SIGST_DETACHED, SIGSUBST_NULL, cpuid);

	stdphys(pa, 7);
	sbdp_cpu_stop_self(pa);

	cmn_err(CE_PANIC, "sbdp_cpu_shutdown_self: CPU %d FAILED TO SHUTDOWN",
	    cpuid);
}

typedef struct {
	int	node;
	int	board;
	int 	non_panther_cpus;
} sbdp_node_walk_t;

static int
sbdp_find_non_panther_cpus(dev_info_t *dip, void *node_args)
{
	int	impl, cpuid, portid;
	int	buflen;
	char	buf[OBP_MAXPROPNAME];
	sbdp_node_walk_t *args = (sbdp_node_walk_t *)node_args;

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_DEVICETYPE, (caddr_t)buf,
	    &buflen) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}

	if (strcmp(buf, "cpu") != 0) {
		return (DDI_WALK_CONTINUE);
	}

	if ((impl = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "implementation#", -1)) == -1) {
		return (DDI_WALK_CONTINUE);
	}

	if ((cpuid = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cpuid", -1)) == -1) {
		return (DDI_WALK_CONTINUE);
	}

	portid = SG_CPUID_TO_PORTID(cpuid);

	/* filter out nodes not on this board */
	if (SG_PORTID_TO_BOARD_NUM(portid) != args->board ||
	    SG_PORTID_TO_NODEID(portid) != args->node) {
		return (DDI_WALK_PRUNECHILD);
	}

	switch (impl) {
	case CHEETAH_IMPL:
	case CHEETAH_PLUS_IMPL:
	case JAGUAR_IMPL:
		args->non_panther_cpus++;
		break;
	case PANTHER_IMPL:
		break;
	default:
		ASSERT(0);
		args->non_panther_cpus++;
		break;
	}

	SBDP_DBG_CPU("cpuid=0x%x, portid=0x%x, impl=0x%x, device_type=%s",
	    cpuid, portid, impl, buf);

	return (DDI_WALK_CONTINUE);
}

int
sbdp_board_non_panther_cpus(int node, int board)
{
	sbdp_node_walk_t arg = {0};

	arg.node = node;
	arg.board = board;

	/*
	 * Root node doesn't have to be held.
	 */
	ddi_walk_devs(ddi_root_node(), sbdp_find_non_panther_cpus,
	    (void *)&arg);

	return (arg.non_panther_cpus);
}
