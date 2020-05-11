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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/lgrp.h>
#include <sys/memnode.h>
#include <sys/promif.h>

#define	EBUS_NAME	"ebus"
#define	RTC_NAME	"rtc"
#define	SHARED_MI2CV_PATH "/i2c@1f,520000"
static dev_info_t *shared_mi2cv_dip;
static kmutex_t chicago_mi2cv_mutex;

/*
 * External variables
 */
extern	volatile uint8_t *v_rtc_addr_reg;

int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);
static void get_ebus_rtc_vaddr(void);

void
startup_platform(void)
{
	mutex_init(&chicago_mi2cv_mutex, NULL, MUTEX_ADAPTIVE, NULL);
}

int
set_platform_tsb_spares()
{
	return (0);
}

void
set_platform_defaults(void)
{
	extern char *tod_module_name;

	/*
	 * We need to set tod_module_name explicitly because there is a
	 * well known South bridge RTC node on chicago and tod_module_name
	 * gets set to that.
	 */
	tod_module_name = "todbq4802";

	/* Work-around for Chicago platform */
	get_ebus_rtc_vaddr();

}

/*
 * Definitions for accessing the pci config space of the isa node
 * of Southbridge.
 */
static ddi_acc_handle_t isa_handle = NULL;	/* handle for isa pci space */


void
load_platform_drivers(void)
{
	/*
	 * Install power driver which handles the power button.
	 */
	if (i_ddi_attach_hw_nodes("power") != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to install \"power\" driver.");
	(void) ddi_hold_driver(ddi_name_to_major("power"));

	/*
	 * It is OK to return error because 'us' driver is not available
	 * in all clusters (e.g. missing in Core cluster).
	 */
	(void) i_ddi_attach_hw_nodes("us");

	if (i_ddi_attach_hw_nodes("grbeep") != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to install \"beep\" driver.");


	/*
	 * mc-us3i must stay loaded for plat_get_mem_unum()
	 */
	if (i_ddi_attach_hw_nodes("mc-us3i") != DDI_SUCCESS)
		cmn_err(CE_WARN, "mc-us3i driver failed to install");
	(void) ddi_hold_driver(ddi_name_to_major("mc-us3i"));

	/*
	 * Figure out which mi2cv dip is shared with OBP for the nvram
	 * device, so the lock can be acquired.
	 */
	shared_mi2cv_dip = e_ddi_hold_devi_by_path(SHARED_MI2CV_PATH, 0);
}

/*ARGSUSED*/
int
plat_cpu_poweron(struct cpu *cp)
{
	return (ENOTSUP);	/* not supported on this platform */
}

/*ARGSUSED*/
int
plat_cpu_poweroff(struct cpu *cp)
{
	return (ENOTSUP);	/* not supported on this platform */
}

/*ARGSUSED*/
void
plat_freelist_process(int mnode)
{
}

char *platform_module_list[] = {
	"mi2cv",
	"jbusppm",
	"pca9556",
	"ppm",
	(char *)0
};

/*ARGSUSED*/
void
plat_tod_fault(enum tod_fault_type tod_bad)
{
}

/*ARGSUSED*/
int
plat_get_mem_unum(int synd_code, uint64_t flt_addr, int flt_bus_id,
    int flt_in_memory, ushort_t flt_status, char *buf, int buflen, int *lenp)
{
	if (flt_in_memory && (p2get_mem_unum != NULL))
		return (p2get_mem_unum(synd_code, P2ALIGN(flt_addr, 8),
		    buf, buflen, lenp));
	else
		return (ENOTSUP);
}

/*ARGSUSED*/
int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	if (snprintf(buf, buflen, "MB") >= buflen) {
		return (ENOSPC);
	} else {
		*lenp = strlen(buf);
		return (0);
	}
}

/*
 * Fiesta support for lgroups.
 *
 * On fiesta platform, an lgroup platform handle == CPU id
 */

/*
 * Macro for extracting the CPU number from the CPU id
 */
#define	CPUID_TO_LGRP(id)	((id) & 0x7)
#define	CHICAGO_MC_SHIFT	36

/*
 * Return the platform handle for the lgroup containing the given CPU
 */
void *
plat_lgrp_cpu_to_hand(processorid_t id)
{
	return ((void *)(uintptr_t)CPUID_TO_LGRP(id));
}

/*
 * Platform specific lgroup initialization
 */
void
plat_lgrp_init(void)
{
	pnode_t		curnode;
	char		tmp_name[sizeof (OBP_CPU)];
	int		portid;
	int		cpucnt = 0;
	int		max_portid = -1;
	extern uint32_t lgrp_expand_proc_thresh;
	extern uint32_t lgrp_expand_proc_diff;
	extern pgcnt_t	lgrp_mem_free_thresh;
	extern uint32_t lgrp_loadavg_tolerance;
	extern uint32_t lgrp_loadavg_max_effect;
	extern uint32_t lgrp_load_thresh;
	extern lgrp_mem_policy_t  lgrp_mem_policy_root;

	/*
	 * Count the number of CPUs installed to determine if
	 * NUMA optimization should be enabled or not.
	 *
	 * All CPU nodes reside in the root node and have a
	 * device type "cpu".
	 */
	curnode = prom_rootnode();
	for (curnode = prom_childnode(curnode); curnode;
	    curnode = prom_nextnode(curnode)) {
		bzero(tmp_name, sizeof (tmp_name));
		if (prom_bounded_getprop(curnode, OBP_DEVICETYPE, tmp_name,
		    sizeof (tmp_name)) == -1 || strcmp(tmp_name, OBP_CPU) != 0)
			continue;

		cpucnt++;
		if (prom_getprop(curnode, "portid", (caddr_t)&portid) !=
		    -1 && portid > max_portid)
			max_portid = portid;
	}
	if (cpucnt <= 1)
		max_mem_nodes = 1;
	else if (max_portid >= 0 && max_portid < MAX_MEM_NODES)
		max_mem_nodes = max_portid + 1;

	/*
	 * Set tuneables for fiesta architecture
	 *
	 * lgrp_expand_proc_thresh is the minimum load on the lgroups
	 * this process is currently running on before considering
	 * expanding threads to another lgroup.
	 *
	 * lgrp_expand_proc_diff determines how much less the remote lgroup
	 * must be loaded before expanding to it.
	 *
	 * Optimize for memory bandwidth by spreading multi-threaded
	 * program to different lgroups.
	 */
	lgrp_expand_proc_thresh = lgrp_loadavg_max_effect - 1;
	lgrp_expand_proc_diff = lgrp_loadavg_max_effect / 2;
	lgrp_loadavg_tolerance = lgrp_loadavg_max_effect / 2;
	lgrp_mem_free_thresh = 1;	/* home lgrp must have some memory */
	lgrp_expand_proc_thresh = lgrp_loadavg_max_effect - 1;
	lgrp_mem_policy_root = LGRP_MEM_POLICY_NEXT;
	lgrp_load_thresh = 0;

	mem_node_pfn_shift = CHICAGO_MC_SHIFT - MMU_PAGESHIFT;
}

/*
 * Return latency between "from" and "to" lgroups
 *
 * This latency number can only be used for relative comparison
 * between lgroups on the running system, cannot be used across platforms,
 * and may not reflect the actual latency.  It is platform and implementation
 * specific, so platform gets to decide its value.  It would be nice if the
 * number was at least proportional to make comparisons more meaningful though.
 * NOTE: The numbers below are supposed to be load latencies for uncached
 * memory divided by 10.
 */
int
plat_lgrp_latency(lgrp_handle_t from, lgrp_handle_t to)
{
	/*
	 * Return remote latency when there are more than two lgroups
	 * (root and child) and getting latency between two different
	 * lgroups or root is involved
	 */
	if (lgrp_optimizations() && (from != to ||
	    from == LGRP_DEFAULT_HANDLE || to == LGRP_DEFAULT_HANDLE))
		return (17);
	else
		return (12);
}

int
plat_pfn_to_mem_node(pfn_t pfn)
{
	ASSERT(max_mem_nodes > 1);
	return (pfn >> mem_node_pfn_shift);
}

/*
 * Assign memnode to lgroups
 */
void
plat_fill_mc(pnode_t nodeid)
{
	int		portid;

	/*
	 * Chicago memory controller portid == global CPU id
	 */
	if ((prom_getprop(nodeid, "portid", (caddr_t)&portid) == -1) ||
	    (portid < 0))
		return;

	if (portid < max_mem_nodes)
		plat_assign_lgrphand_to_mem_node((lgrp_handle_t)portid, portid);
}

/*
 * Common locking enter code
 */
void
plat_setprop_enter(void)
{
	mutex_enter(&chicago_mi2cv_mutex);
}

/*
 * Common locking exit code
 */
void
plat_setprop_exit(void)
{
	mutex_exit(&chicago_mi2cv_mutex);
}

/*
 * Called by mi2cv driver
 */
void
plat_shared_i2c_enter(dev_info_t *i2cnexus_dip)
{
	if (i2cnexus_dip == shared_mi2cv_dip) {
		plat_setprop_enter();
	}
}

/*
 * Called by mi2cv driver
 */
void
plat_shared_i2c_exit(dev_info_t *i2cnexus_dip)
{
	if (i2cnexus_dip == shared_mi2cv_dip) {
		plat_setprop_exit();
	}
}

/*
 * Work-around for the Chicago platform.
 * There are two RTCs in the Chicago platform, one on the Southbridge
 * and one on the EBUS.
 * In the current Solaris implementation, have_rtc in sun4u/os/fillsysinfo.c
 * returns address of the first rtc it sees. In this case, it's the SB RTC.
 *
 * get_ebus_rtc_vaddr() looks for the EBUS RTC and setup the right address.
 * If there is no EBUS RTC node or the RTC node does not have the valid
 * address property, get_ebus_rtc_vaddr() will fail.
 */
static void
get_ebus_rtc_vaddr()
{
	pnode_t node;
	int size;
	uint32_t eaddr;

	/* Find ebus RTC node */
	if ((node = prom_findnode_byname(prom_rootnode(),
	    EBUS_NAME)) == OBP_NONODE)
		cmn_err(CE_PANIC, "ebus node not present\n");
	if ((node = prom_findnode_byname(node, RTC_NAME)) == OBP_NONODE)
		cmn_err(CE_PANIC, "ebus RTC node not found\n");

	/* Make sure the ebus RTC address property is valid */
	if ((size = prom_getproplen(node, "address")) == -1)
		cmn_err(CE_PANIC, "ebus RTC addr prop. length not found\n");
	if (size != sizeof (eaddr))
		cmn_err(CE_PANIC, "ebus RTC addr length not OK."
		    " expected = %lu found =%d\n", sizeof (eaddr), size);
	if (prom_getprop(node, "address", (caddr_t)&eaddr) == -1)
		cmn_err(CE_PANIC, "ebus RTC addr propery not found\n");
	v_rtc_addr_reg = (volatile unsigned char *)(uintptr_t)eaddr;

	/*
	 * Does this rtc have watchdog support?
	 */
	if (prom_getproplen(node, "watchdog-enable") != -1)
		watchdog_available = 1;
}
