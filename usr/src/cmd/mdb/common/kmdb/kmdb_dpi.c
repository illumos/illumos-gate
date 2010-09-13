/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The DPI, or debugger/PROM interface, is used to isolate the debugger from the
 * means by which we use the PROM to control the machine.
 */

#include <sys/types.h>
#include <setjmp.h>

#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_auxv.h>
#include <kmdb/kmdb_wr_impl.h>
#include <kmdb/kmdb_module.h>
#include <kmdb/kmdb_start.h>
#include <kmdb/kmdb_asmutil.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>

jmp_buf *kmdb_dpi_fault_pcb;
jmp_buf kmdb_dpi_resume_pcb;
jmp_buf kmdb_dpi_entry_pcb;

static int kmdb_dpi_state;
static int kmdb_dpi_state_why;

uint_t kmdb_dpi_resume_requested;
uint_t kmdb_dpi_switch_target = (uint_t)-1;

/* Used by the style-specific resume interfaces to signal the driver */
void (*kmdb_dpi_wrintr_fire)(void);

int
kmdb_dpi_init(kmdb_auxv_t *kav)
{
	kmdb_dpi_state = DPI_STATE_INIT;
	kmdb_dpi_resume_requested = 0;
	kmdb_dpi_wrintr_fire = kav->kav_wrintr_fire;

	mdb.m_dpi = &kmdb_dpi_ops;
	return (mdb.m_dpi->dpo_init(kav));
}

/*ARGSUSED1*/
void
kmdb_activate(kdi_debugvec_t **dvecp, uint_t flags)
{
	mdb.m_dpi->dpo_debugger_activate(dvecp, flags);
}

void
kmdb_deactivate(void)
{
	mdb.m_dpi->dpo_debugger_deactivate();
}

int
kmdb_dpi_reenter(void)
{
	int cmd;

	kmdb_kdi_system_claim();

	if ((cmd = setjmp(kmdb_dpi_entry_pcb)) == 0) {
		/* Direct entry from the driver */
		if (kmdb_dpi_resume_requested)
			longjmp(kmdb_dpi_resume_pcb, 1);

		kmdb_first_start();

		fail("kmdb_first_start returned");
		/*NOTREACHED*/
	}

	mdb_dprintf(MDB_DBG_DPI, "returning to driver - cmd %d%s\n", cmd,
	    (kmdb_dpi_work_required() ? " (work required)" : ""));

	kmdb_kdi_system_release();

	membar_producer();

	/*
	 * The debugger wants us to do something - it returned a command
	 * via the setjmp().  The driver will know what to do with the
	 * command.
	 */
	return (cmd);
}

void
kmdb_dpi_enter_mon(void)
{
	mdb.m_dpi->dpo_enter_mon();
}

void
kmdb_dpi_modchg_register(void (*func)(struct modctl *, int))
{
	mdb.m_dpi->dpo_modchg_register(func);
}

void
kmdb_dpi_modchg_cancel(void)
{
	mdb.m_dpi->dpo_modchg_cancel();
}

int
kmdb_dpi_get_cpu_state(int cpuid)
{
	return (mdb.m_dpi->dpo_get_cpu_state(cpuid));
}

int
kmdb_dpi_get_master_cpuid(void)
{
	return (mdb.m_dpi->dpo_get_master_cpuid());
}

const mdb_tgt_gregset_t *
kmdb_dpi_get_gregs(int cpuid)
{
	return (mdb.m_dpi->dpo_get_gregs(cpuid));
}

jmp_buf *
kmdb_dpi_set_fault_hdlr(jmp_buf *jb)
{
	jmp_buf *oldpcb = kmdb_dpi_fault_pcb;

	kmdb_dpi_fault_pcb = jb;

	return (oldpcb);
}

void
kmdb_dpi_restore_fault_hdlr(jmp_buf *jb)
{
	(void) kmdb_dpi_set_fault_hdlr(jb);
}

/*
 * Used to tell the driver that it needs to do work after the resume.
 *
 * CAUTION: This routine may be called *after* mdb_destroy
 */
int
kmdb_dpi_work_required(void)
{
	return (kmdb_kdi_get_unload_request() ||
	    !kmdb_wr_driver_notify_isempty());
}

void
kmdb_dpi_resume_master(void)
{
	kmdb_dpi_resume_common(KMDB_DPI_CMD_RESUME_MASTER);
}

void
kmdb_dpi_resume(void)
{
	kmdb_dpi_resume_common(KMDB_DPI_CMD_RESUME_ALL);
}

void
kmdb_dpi_resume_unload(void)
{
	kmdb_dpi_resume_common(KMDB_DPI_CMD_RESUME_UNLOAD);
}

int
kmdb_dpi_switch_master(int tgt_cpuid)
{
	if (kmdb_dpi_get_cpu_state(tgt_cpuid) < 0)
		return (-1); /* errno is set for us */

	kmdb_dpi_switch_target = tgt_cpuid;
	kmdb_dpi_resume_common(KMDB_DPI_CMD_SWITCH_CPU);

	return (0);
}

void
kmdb_dpi_flush_slave_caches(void)
{
	kmdb_dpi_resume_common(KMDB_DPI_CMD_FLUSH_CACHES);
}

typedef struct work_results {
	mdb_nv_t res_loads;
	mdb_nv_t res_unloads;
} work_results_t;

static int
kmdb_dbgnotify_cb(kmdb_wr_t *wn, void *arg)
{
	work_results_t *res = arg;

	switch (WR_TASK(wn)) {
	case WNTASK_DMOD_LOAD: {
		/*
		 * If this is an ack, the driver finished processing a load we
		 * requested.  We process it and free the message.  If this
		 * isn't an ack, then it's a driver-initiated load.  We process
		 * the message, and send it back as an ack so the driver can
		 * free it.
		 */
		kmdb_wr_load_t *dlr = (kmdb_wr_load_t *)wn;

		mdb_dprintf(MDB_DBG_DPI, "received module load message\n");

		if (kmdb_module_loaded(dlr) && res != NULL) {
			(void) mdb_nv_insert(&res->res_loads,
			    strbasename(dlr->dlr_fname), NULL, 0, 0);
		}

		if (WR_ISACK(dlr)) {
			kmdb_module_load_ack(dlr);
			return (0);
		}

		/* Send it back as an ack */
		mdb_dprintf(MDB_DBG_DPI, "Sending load request for %s back "
		    "as an ack\n", dlr->dlr_fname);
		WR_ACK(wn);
		kmdb_wr_driver_notify(wn);
		return (0);
	}

	case WNTASK_DMOD_LOAD_ALL:
		/*
		 * We initiated the load-all, so this must be an ack.  The
		 * individual module load messages will arrive separately -
		 * there's no need to do anything further with this message.
		 */
		ASSERT(WR_ISACK(wn));

		mdb_dprintf(MDB_DBG_DPI, "received module load all ack\n");

		kmdb_module_load_all_ack(wn);
		return (0);

	case WNTASK_DMOD_UNLOAD: {
		/*
		 * The debugger received an unload message.  The driver isn't
		 * supposed to initiate unloads, so we shouldn't see anything
		 * but acks.  We tell the dmod subsystem that the module has
		 * been unloaded, and we free the message.
		 */
		kmdb_wr_unload_t *dur = (kmdb_wr_unload_t *)wn;

		ASSERT(WR_ISACK(dur));

		mdb_dprintf(MDB_DBG_DPI, "received module unload ack\n");

		if (kmdb_module_unloaded(dur) && res != NULL) {
			(void) mdb_nv_insert(&res->res_unloads,
			    dur->dur_modname, NULL, 0, 0);
		}

		/* Done with message */
		kmdb_module_unload_ack(dur);
		return (0);
	}

	case WNTASK_DMOD_PATH_CHANGE: {
		/*
		 * The debugger received a path change message.  The driver
		 * can't initiate these, so it must be an acknowledgement.
		 * There's no processing to be done, so just free the message.
		 */
		kmdb_wr_path_t *dpth = (kmdb_wr_path_t *)wn;

		ASSERT(WR_ISACK(dpth));

		mdb_dprintf(MDB_DBG_DPI, "received path change ack\n");

		kmdb_module_path_ack(dpth);
		return (0);
	}

	default:
		mdb_warn("Received unknown message type %d from driver\n",
		    wn->wn_task);
		/* Ignore it */
		return (0);
	}
}

static void
print_modules(mdb_nv_t *mods)
{
	mdb_var_t *v;

	mdb_nv_rewind(mods);
	while ((v = mdb_nv_advance(mods)) != NULL)
		mdb_printf(" %s", mdb_nv_get_name(v));
}

void
kmdb_dpi_process_work_queue(void)
{
	work_results_t res;

	(void) mdb_nv_create(&res.res_loads, UM_SLEEP);
	(void) mdb_nv_create(&res.res_unloads, UM_SLEEP);

	mdb_dprintf(MDB_DBG_DPI, "processing work queue\n");
	(void) kmdb_wr_debugger_process(kmdb_dbgnotify_cb, &res);

	if (mdb_nv_size(&res.res_loads)) {
		mdb_printf("Loaded modules: [");
		print_modules(&res.res_loads);
		mdb_printf(" ]\n");
	}

	if (mdb_nv_size(&res.res_unloads)) {
		mdb_printf("Unloaded modules: [");
		print_modules(&res.res_unloads);
		mdb_printf(" ]\n");
	}

	mdb_nv_destroy(&res.res_loads);
	mdb_nv_destroy(&res.res_unloads);
}

int
kmdb_dpi_step(void)
{
	return (mdb.m_dpi->dpo_step());
}

uintptr_t
kmdb_dpi_call(uintptr_t func, uint_t argc, const uintptr_t *argv)
{
	return (mdb.m_dpi->dpo_call(func, argc, argv));
}

int
kmdb_dpi_brkpt_arm(uintptr_t addr, mdb_instr_t *instrp)
{
	int rc;

	if ((rc = mdb.m_dpi->dpo_brkpt_arm(addr, instrp)) < 0)
		mdb_warn("failed to arm breakpoint at %a", addr);

	mdb_dprintf(MDB_DBG_DPI, "brkpt armed at %p %A\n", (void *)addr, addr);

	return (rc);
}

int
kmdb_dpi_brkpt_disarm(uintptr_t addr, mdb_instr_t instrp)
{
	int rc;

	if ((rc = mdb.m_dpi->dpo_brkpt_disarm(addr, instrp)) < 0)
		mdb_warn("failed to disarm breakpoint at %a", addr);

	mdb_dprintf(MDB_DBG_DPI, "brkpt disarmed at %p %A\n", (void *)addr,
	    addr);

	return (rc);
}

int
kmdb_dpi_wapt_validate(kmdb_wapt_t *wp)
{
	if (mdb.m_dpi->dpo_wapt_validate(wp) < 0)
		return (-1); /* errno is set for us */

	return (0);
}

int
kmdb_dpi_wapt_reserve(kmdb_wapt_t *wp)
{
	if (mdb.m_dpi->dpo_wapt_reserve(wp) < 0)
		return (-1); /* errno is set for us */

	mdb_dprintf(MDB_DBG_DPI, "wapt reserve type %d at %p, priv %p\n",
	    wp->wp_type, (void *)wp->wp_addr, wp->wp_priv);

	return (0);
}

void
kmdb_dpi_wapt_release(kmdb_wapt_t *wp)
{
	mdb.m_dpi->dpo_wapt_release(wp);
}

void
kmdb_dpi_wapt_arm(kmdb_wapt_t *wp)
{
	mdb.m_dpi->dpo_wapt_arm(wp);

	mdb_dprintf(MDB_DBG_DPI, "wapt armed at %p (type %d, priv %p)\n",
	    (void *)wp->wp_addr, wp->wp_type, wp->wp_priv);
}

void
kmdb_dpi_wapt_disarm(kmdb_wapt_t *wp)
{
	mdb.m_dpi->dpo_wapt_disarm(wp);

	mdb_dprintf(MDB_DBG_DPI, "wapt disarmed at %p (type %d, priv %p)\n",
	    (void *)wp->wp_addr, wp->wp_type, wp->wp_priv);
}

int
kmdb_dpi_wapt_match(kmdb_wapt_t *wp)
{
	return (mdb.m_dpi->dpo_wapt_match(wp));
}

void
kmdb_dpi_set_state(int state, int why)
{
	if (kmdb_dpi_state != DPI_STATE_LOST) {
		mdb_dprintf(MDB_DBG_DPI, "dpi_set_state %d why %d\n",
		    state, why);

		kmdb_dpi_state = state;
		kmdb_dpi_state_why = why;
	}
}

int
kmdb_dpi_get_state(int *whyp)
{
	if (whyp != NULL)
		*whyp = kmdb_dpi_state_why;

	return (kmdb_dpi_state);
}

void
kmdb_dpi_dump_crumbs(uintptr_t addr, int cpuid)
{
	mdb.m_dpi->dpo_dump_crumbs(addr, cpuid);
}
