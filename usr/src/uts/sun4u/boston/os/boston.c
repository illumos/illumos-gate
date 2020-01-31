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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>

#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/rmc_comm_dp.h>
#include <sys/rmc_comm_drvintf.h>
#include <sys/modctl.h>
#include <sys/lgrp.h>
#include <sys/memnode.h>
#include <sys/promif.h>

#define	SHARED_MI2CV_PATH "/i2c@1f,520000"
static dev_info_t *shared_mi2cv_dip;
static kmutex_t mi2cv_mutex;

int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);
static void cpu_sgn_update(ushort_t, uchar_t, uchar_t, int);
int (*rmc_req_now)(rmc_comm_msg_t *, uint8_t) = NULL;

void
startup_platform(void)
{
	mutex_init(&mi2cv_mutex, NULL, MUTEX_ADAPTIVE, NULL);
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
	/* Set appropriate tod module */
	if (tod_module_name == NULL)
		tod_module_name = "todm5823";

	cpu_sgn_func = cpu_sgn_update;
}

/*
 * these two dummy functions are loaded over the original
 * todm5823 set and clear_power_alarm functions. On Boston
 * these functions are not supported, and thus we need to provide
 * dummy functions that just returns.
 * On Boston, clock chip is not persistant across reboots,
 * and moreover it has a bug sending memory access.
 * This fix is done by writing over the original
 * tod_ops function pointer with our dummy replacement functions.
 */
/*ARGSUSED*/
static void
dummy_todm5823_set_power_alarm(timestruc_t ts)
{
}

static void
dummy_todm5823_clear_power_alarm(void)
{
}

/*
 * Definitions for accessing the pci config space of the isa node
 * of Southbridge.
 */
static ddi_acc_handle_t isa_handle = NULL;	/* handle for isa pci space */

/*
 * Definition for accessing rmclomv
 */
#define	RMCLOMV_PATHNAME	"/pseudo/rmclomv@0"

void
load_platform_drivers(void)
{
	/*
	 * It is OK to return error because 'us' driver is not available
	 * in all clusters (e.g. missing in Core cluster).
	 */
	(void) i_ddi_attach_hw_nodes("us");


	/*
	 * mc-us3i must stay loaded for plat_get_mem_unum()
	 */
	if (i_ddi_attach_hw_nodes("mc-us3i") != DDI_SUCCESS)
		cmn_err(CE_WARN, "mc-us3i driver failed to install");
	(void) ddi_hold_driver(ddi_name_to_major("mc-us3i"));

	/*
	 * load the power button driver
	 */
	if (i_ddi_attach_hw_nodes("power") != DDI_SUCCESS)
		cmn_err(CE_WARN, "power button driver failed to install");
	(void) ddi_hold_driver(ddi_name_to_major("power"));

	/*
	 * load the GPIO driver for the ALOM reset and watchdog lines
	 */
	if (i_ddi_attach_hw_nodes("pmugpio") != DDI_SUCCESS)
		cmn_err(CE_WARN, "pmugpio failed to install");
	else {
		extern int watchdog_enable, watchdog_available;
		extern int disable_watchdog_on_exit;

		/*
		 * Disable an active h/w watchdog timer upon exit to OBP.
		 */
		disable_watchdog_on_exit = 1;

		watchdog_enable = 1;
		watchdog_available = 1;
	}
	(void) ddi_hold_driver(ddi_name_to_major("pmugpio"));

	/*
	 * Figure out which mi2cv dip is shared with OBP for the nvram
	 * device, so the lock can be acquired.
	 */
	shared_mi2cv_dip = e_ddi_hold_devi_by_path(SHARED_MI2CV_PATH, 0);

	/*
	 * Load the environmentals driver (rmclomv)
	 *
	 * We need this driver to handle events from the RMC when state
	 * changes occur in the environmental data.
	 */
	if (i_ddi_attach_hw_nodes("rmc_comm") != DDI_SUCCESS) {
		cmn_err(CE_WARN, "rmc_comm failed to install");
	} else {
		(void) ddi_hold_driver(ddi_name_to_major("rmc_comm"));

		if (e_ddi_hold_devi_by_path(RMCLOMV_PATHNAME, 0) == NULL) {
			cmn_err(CE_WARN, "Could not install rmclomv driver\n");
		}
	}

	/*
	 * These two dummy functions are loaded over the original
	 * todm5823 set and clear_power_alarm functions. On Boston,
	 * these functionalities are not supported.
	 * The load_platform_drivers(void) is called from post_startup()
	 * which is after all the initialization of the tod module is
	 * finished, then we replace 2 of the tod_ops function pointers
	 * with our dummy version.
	 */
	tod_ops.tod_set_power_alarm = dummy_todm5823_set_power_alarm;
	tod_ops.tod_clear_power_alarm = dummy_todm5823_clear_power_alarm;

	/*
	 * create a handle to the rmc_comm_request_nowait() function
	 * inside the rmc_comm module.
	 *
	 * The Seattle/Boston todm5823 driver will use this handle to
	 * use the rmc_comm_request_nowait() function to send time/date
	 * updates to ALOM.
	 */
	rmc_req_now = (int (*)(rmc_comm_msg_t *, uint8_t))
	    modgetsymvalue("rmc_comm_request_nowait", 0);
}

/*
 * This routine is needed if a device error or timeout occurs before the
 * driver is loaded.
 */
/*ARGSUSED*/
int
plat_ide_chipreset(dev_info_t *dip, int chno)
{
	int	ret = DDI_SUCCESS;

	if (isa_handle == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * This will be filled in with the reset logic
	 * for the ULI1573 when that becomes available.
	 * currently this is just a stub.
	 */
	return (ret);
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
	"pca9556",
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

/*
 * This platform hook gets called from mc_add_mem_unum_label() in the mc-us3i
 * driver giving each platform the opportunity to add platform
 * specific label information to the unum for ECC error logging purposes.
 */
/*ARGSUSED*/
void
plat_add_mem_unum_label(char *unum, int mcid, int bank, int dimm)
{
	char old_unum[UNUM_NAMLEN];
	int printed;
	int buflen = UNUM_NAMLEN;

	(void) strcpy(old_unum, unum);
	printed = snprintf(unum, buflen, "MB/C%d/P0/B%d", mcid, bank);
	buflen -= printed;
	unum += printed;

	if (dimm != -1) {
		printed = snprintf(unum, buflen, "/D%d", dimm);
		buflen -= printed;
		unum += printed;
	}

	(void) snprintf(unum, buflen, ": %s", old_unum);
}

/*ARGSUSED*/
int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	if (snprintf(buf, buflen, "MB/C%d", cpuid) >= buflen) {
		return (ENOSPC);
	} else {
		*lenp = strlen(buf);
		return (0);
	}
}

/*
 * Our nodename has been set, pass it along to the RMC.
 */
void
plat_nodename_set(void)
{
	rmc_comm_msg_t	req;	/* request */
	int (*rmc_req_res)(rmc_comm_msg_t *, rmc_comm_msg_t *, time_t) = NULL;

	/*
	 * find the symbol for the mailbox routine
	 */
	rmc_req_res = (int (*)(rmc_comm_msg_t *, rmc_comm_msg_t *, time_t))
	    modgetsymvalue("rmc_comm_request_response", 0);

	if (rmc_req_res == NULL) {
		return;
	}

	/*
	 * construct the message telling the RMC our nodename
	 */
	req.msg_type = DP_SET_CPU_NODENAME;
	req.msg_len = strlen(utsname.nodename) + 1;
	req.msg_bytes = 0;
	req.msg_buf = (caddr_t)utsname.nodename;

	/*
	 * ship it
	 */
	(void) (rmc_req_res)(&req, NULL, 2000);
}

sig_state_t current_sgn;

/*
 * cpu signatures - we're only interested in the overall system
 * "signature" on this platform - not individual cpu signatures
 */
/*ARGSUSED*/
static void
cpu_sgn_update(ushort_t sig, uchar_t state, uchar_t sub_state, int cpuid)
{
	dp_cpu_signature_t signature;
	rmc_comm_msg_t	req;	/* request */
	int (*rmc_req_now)(rmc_comm_msg_t *, uint8_t) = NULL;


	/*
	 * Differentiate a panic reboot from a non-panic reboot in the
	 * setting of the substate of the signature.
	 *
	 * If the new substate is REBOOT and we're rebooting due to a panic,
	 * then set the new substate to a special value indicating a panic
	 * reboot, SIGSUBST_PANIC_REBOOT.
	 *
	 * A panic reboot is detected by a current (previous) signature
	 * state of SIGST_EXIT, and a new signature substate of SIGSUBST_REBOOT.
	 * The domain signature state SIGST_EXIT is used as the panic flow
	 * progresses.
	 *
	 * At the end of the panic flow, the reboot occurs but we should know
	 * one that was involuntary, something that may be quite useful to know
	 * at OBP level.
	 */
	if (state == SIGST_EXIT && sub_state == SIGSUBST_REBOOT) {
		if (current_sgn.state_t.state == SIGST_EXIT &&
		    current_sgn.state_t.sub_state != SIGSUBST_REBOOT)
			sub_state = SIGSUBST_PANIC_REBOOT;
	}

	/*
	 * offline and detached states only apply to a specific cpu
	 * so ignore them.
	 */
	if (state == SIGST_OFFLINE || state == SIGST_DETACHED) {
		return;
	}

	current_sgn.signature = CPU_SIG_BLD(sig, state, sub_state);

	/*
	 * find the symbol for the mailbox routine
	 */
	rmc_req_now = (int (*)(rmc_comm_msg_t *, uint8_t))
	    modgetsymvalue("rmc_comm_request_nowait", 0);
	if (rmc_req_now == NULL) {
		return;
	}

	signature.cpu_id = -1;
	signature.sig = sig;
	signature.states = state;
	signature.sub_state = sub_state;
	req.msg_type = DP_SET_CPU_SIGNATURE;
	req.msg_len = (int)(sizeof (signature));
	req.msg_bytes = 0;
	req.msg_buf = (caddr_t)&signature;

	/*
	 * We need to tell the SP that the host is about to stop running.  The
	 * SP will then allow the date to be set at its console, it will change
	 * state of the activity indicator, it will display the correct host
	 * status, and it will stop sending console messages and alerts to the
	 * host communication channel.
	 *
	 * This requires the RMC_COMM_DREQ_URGENT as we want to
	 * be sure activity indicators will reflect the correct status.
	 *
	 * When sub_state SIGSUBST_DUMP is sent, the urgent flag
	 * (RMC_COMM_DREQ_URGENT) is not required as SIGSUBST_PANIC_REBOOT
	 * has already been sent and changed activity indicators.
	 */
	if (state == SIGST_EXIT && (sub_state == SIGSUBST_HALT ||
	    sub_state == SIGSUBST_REBOOT || sub_state == SIGSUBST_ENVIRON ||
	    sub_state == SIGSUBST_PANIC_REBOOT))
		(void) (rmc_req_now)(&req, RMC_COMM_DREQ_URGENT);
	else
		(void) (rmc_req_now)(&req, 0);
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
#define	PLATFORM_MC_SHIFT	36

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
	char		tmp_name[sizeof (OBP_CPU) + 1];  /* extra padding */
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
		bzero(tmp_name,  sizeof (tmp_name));
		if (prom_bounded_getprop(curnode, OBP_DEVICETYPE, tmp_name,
		    sizeof (OBP_CPU)) == -1 || strcmp(tmp_name, OBP_CPU) != 0)
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

	mem_node_pfn_shift = PLATFORM_MC_SHIFT - MMU_PAGESHIFT;
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
plat_lgrp_latency(void *from, void *to)
{
	/*
	 * Return remote latency when there are more than two lgroups
	 * (root and child) and getting latency between two different
	 * lgroups or root is involved
	 */
	if (lgrp_optimizations() && (from != to || from ==
	    (void *) LGRP_DEFAULT_HANDLE || to == (void *) LGRP_DEFAULT_HANDLE))
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
	 * Memory controller portid == global CPU id
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
	mutex_enter(&mi2cv_mutex);
}

/*
 * Common locking exit code
 */
void
plat_setprop_exit(void)
{
	mutex_exit(&mi2cv_mutex);
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
 * Called by todm5823 driver
 */
void
plat_rmc_comm_req(struct rmc_comm_msg *request)
{
	if (rmc_req_now)
		(void) rmc_req_now(request, 0);
}
