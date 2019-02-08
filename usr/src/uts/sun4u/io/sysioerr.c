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
 * Copyright 1990-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/cmn_err.h>
#include <sys/async.h>
#include <sys/sysiosbus.h>
#include <sys/sysioerr.h>
#include <sys/x_call.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/vmsystm.h>
#include <sys/cpu_module.h>

/*
 * Set the following variable in /etc/system to tell the kernel
 * not to shutdown the machine if the temperature reaches
 * the Thermal Warning limit.
 */
int oven_test = 0;

/*
 * To indicate if the prom has the property of "thermal-interrupt".
 */
static int thermal_interrupt_enabled = 0;

/*
 * adb debug_sysio_errs to 1 if you don't want your system to panic on
 * sbus ue errors. adb sysio_err_flag to 0 if you don't want your system
 * to check for sysio errors at all.
 */
int sysio_err_flag = 1;
uint_t debug_sysio_errs = 0;

/*
 * bto_cnt = number of bus errors and timeouts allowed within bto_secs
 * use /etc/system to change the bto_cnt to a very large number if
 * it's a problem!
 */
int bto_secs = 10;
int bto_cnt = 10;

static uint_t
sysio_ue_intr(struct sbus_soft_state *softsp);

static uint_t
sysio_ce_intr(struct sbus_soft_state *softsp);

static uint_t
sbus_err_intr(struct sbus_soft_state *softsp);

static void
sysio_log_ce_err(struct async_flt *ecc, char *unum);

static void
sysio_log_ue_err(struct async_flt *ecc, char *unum);

static void
sbus_clear_intr(struct sbus_soft_state *softsp, uint64_t *pafsr);

static void
sbus_log_error(struct sbus_soft_state *softsp, uint64_t *pafsr, uint64_t *pafar,
    ushort_t id, ushort_t inst, int cleared,
    on_trap_data_t *ontrap_data);

static int
sbus_check_bto(struct sbus_soft_state *softsp);

static void
sbus_log_csr_error(struct async_flt *aflt, char *unum);

static uint_t
sbus_ctrl_ecc_err(struct sbus_soft_state *softsp);

static uint_t
sysio_dis_err(struct sbus_soft_state *softsp);

static uint_t
sysio_init_err(struct sbus_soft_state *softsp);

static uint_t
sysio_thermal_warn_intr(struct sbus_soft_state *softsp);

static int sbus_pil[] = {SBUS_UE_PIL, SBUS_CE_PIL, SBUS_ERR_PIL, SBUS_PF_PIL,
	SBUS_THERMAL_PIL, SBUS_PM_PIL};
int
sysio_err_init(struct sbus_soft_state *softsp, caddr_t address)
{
	if (sysio_err_flag == 0) {
		cmn_err(CE_CONT, "Warning: sysio errors not initialized\n");
		return (DDI_SUCCESS);
	}

	/*
	 * Get the address of the already mapped-in sysio/sbus error registers.
	 * Simply add each registers offset to the already mapped in address
	 * that was retrieved from the device node's "address" property,
	 * and passed as an argument to this function.
	 *
	 * Define a macro for the pointer arithmetic ...
	 */

#define	REG_ADDR(b, o)	(uint64_t *)((caddr_t)(b) + (o))

	softsp->sysio_ecc_reg = REG_ADDR(address, OFF_SYSIO_ECC_REGS);
	softsp->sysio_ue_reg = REG_ADDR(address, OFF_SYSIO_UE_REGS);
	softsp->sysio_ce_reg = REG_ADDR(address, OFF_SYSIO_CE_REGS);
	softsp->sbus_err_reg = REG_ADDR(address, OFF_SBUS_ERR_REGS);

#undef	REG_ADDR

	/*
	 * create the interrupt-priorities property if it doesn't
	 * already exist to provide a hint as to the PIL level for
	 * our interrupt.
	 */
	{
		int len;

		if (ddi_getproplen(DDI_DEV_T_ANY, softsp->dip,
		    DDI_PROP_DONTPASS, "interrupt-priorities",
		    &len) != DDI_PROP_SUCCESS) {
				/* Create the interrupt-priorities property. */
			(void) ddi_prop_update_int_array(DDI_DEV_T_NONE,
			    softsp->dip, "interrupt-priorities",
			    (int *)sbus_pil, sizeof (sbus_pil) / sizeof (int));
		}
	}

	(void) ddi_add_intr(softsp->dip, 0, NULL, NULL,
	    (uint_t (*)())sysio_ue_intr, (caddr_t)softsp);
	(void) ddi_add_intr(softsp->dip, 1, NULL, NULL,
	    (uint_t (*)())sysio_ce_intr, (caddr_t)softsp);
	(void) ddi_add_intr(softsp->dip, 2, NULL, NULL,
	    (uint_t (*)())sbus_err_intr, (caddr_t)softsp);
	/*
	 * If the thermal-interrupt property is in place,
	 * then register the thermal warning interrupt handler and
	 * program its mapping register
	 */
	thermal_interrupt_enabled = ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
		DDI_PROP_DONTPASS, "thermal-interrupt", -1);

	if (thermal_interrupt_enabled == 1) {
		(void) ddi_add_intr(softsp->dip, 4, NULL, NULL,
		    (uint_t (*)())sysio_thermal_warn_intr, (caddr_t)softsp);
	}

	bus_func_register(BF_TYPE_UE, (busfunc_t)sbus_ctrl_ecc_err, softsp);
	bus_func_register(BF_TYPE_ERRDIS, (busfunc_t)sysio_dis_err, softsp);

	(void) sysio_init_err(softsp);

	return (DDI_SUCCESS);
}

int
sysio_err_resume_init(struct sbus_soft_state *softsp)
{
	(void) sysio_init_err(softsp);
	return (DDI_SUCCESS);
}

int
sysio_err_uninit(struct sbus_soft_state *softsp)
{
	/* remove the interrupts from the interrupt list */
	(void) sysio_dis_err(softsp);

	ddi_remove_intr(softsp->dip, 0, NULL);
	ddi_remove_intr(softsp->dip, 1, NULL);
	ddi_remove_intr(softsp->dip, 2, NULL);

	if (thermal_interrupt_enabled == 1) {
		ddi_remove_intr(softsp->dip, 4, NULL);
	}

	bus_func_unregister(BF_TYPE_UE, (busfunc_t)sbus_ctrl_ecc_err, softsp);
	bus_func_unregister(BF_TYPE_ERRDIS, (busfunc_t)sysio_dis_err, softsp);

	return (DDI_SUCCESS);
}

static uint_t
sysio_init_err(struct sbus_soft_state *softsp)
{
	volatile uint64_t tmp_mondo_vec, tmpreg;
	volatile uint64_t *mondo_vec_reg;
	uint_t cpu_id, acpu_id;

	acpu_id = intr_dist_cpuid();
	/*
	 * Program the mondo vector accordingly.  This MUST be the
	 * last thing we do.  Once we program the mondo, the device
	 * may begin to interrupt. Store it in the hardware reg.
	 */
	mondo_vec_reg = (uint64_t *)(softsp->intr_mapping_reg + UE_ECC_MAPREG);
	cpu_id = acpu_id;
	tmp_mondo_vec = (cpu_id << INTERRUPT_CPU_FIELD) | INTERRUPT_VALID;
	*mondo_vec_reg = tmp_mondo_vec;

	mondo_vec_reg = (uint64_t *)(softsp->intr_mapping_reg + CE_ECC_MAPREG);
	cpu_id = acpu_id;
	tmp_mondo_vec = (cpu_id << INTERRUPT_CPU_FIELD) | INTERRUPT_VALID;
	*mondo_vec_reg = tmp_mondo_vec;

	mondo_vec_reg =
	    (uint64_t *)(softsp->intr_mapping_reg + SBUS_ERR_MAPREG);
	cpu_id = acpu_id;

	tmp_mondo_vec = (cpu_id << INTERRUPT_CPU_FIELD) | INTERRUPT_VALID;
	*mondo_vec_reg = tmp_mondo_vec;

	if (thermal_interrupt_enabled == 1) {
		mondo_vec_reg = (softsp->intr_mapping_reg + THERMAL_MAPREG);
		cpu_id = acpu_id;
		tmp_mondo_vec = (cpu_id << INTERRUPT_CPU_FIELD) |
			INTERRUPT_VALID;
		*mondo_vec_reg = tmp_mondo_vec;
	}

	/* Flush store buffers */
	tmpreg = *softsp->sbus_ctrl_reg;

	/*
	 * XXX - This may already be set by the OBP.
	 */
	tmpreg = SYSIO_APCKEN;
	*softsp->sysio_ctrl_reg |= tmpreg;
	tmpreg = (SECR_ECC_EN | SECR_UE_INTEN | SECR_CE_INTEN);
	*softsp->sysio_ecc_reg = tmpreg;
	tmpreg = SB_CSR_ERRINT_EN;
	*softsp->sbus_err_reg |= tmpreg;

	/* Initialize timeout/bus error counter */
	softsp->bto_timestamp = 0;
	softsp->bto_ctr = 0;

	return (0);
}

static uint_t
sysio_dis_err(struct sbus_soft_state *softsp)
{
	volatile uint64_t tmpreg;
	volatile uint64_t *mondo_vec_reg, *clear_vec_reg;

	*softsp->sysio_ctrl_reg &= ~SYSIO_APCKEN;
	*softsp->sysio_ecc_reg = 0;
	*softsp->sbus_err_reg &= ~SB_CSR_ERRINT_EN;

	/* Flush store buffers */
	tmpreg = *softsp->sbus_ctrl_reg;
#ifdef lint
	tmpreg = tmpreg;
#endif

	/* Unmap mapping registers */
	mondo_vec_reg = (softsp->intr_mapping_reg + UE_ECC_MAPREG);
	clear_vec_reg = (softsp->clr_intr_reg + UE_ECC_CLEAR);

	*mondo_vec_reg = 0;

	*clear_vec_reg = 0;

	mondo_vec_reg = (softsp->intr_mapping_reg + CE_ECC_MAPREG);
	clear_vec_reg = (softsp->clr_intr_reg + CE_ECC_CLEAR);

	*mondo_vec_reg = 0;

	*clear_vec_reg = 0;

	mondo_vec_reg = (softsp->intr_mapping_reg + SBUS_ERR_MAPREG);
	clear_vec_reg = (softsp->clr_intr_reg + SBUS_ERR_CLEAR);

	*mondo_vec_reg = 0;

	*clear_vec_reg = 0;

	/* Flush store buffers */
	tmpreg = *softsp->sbus_ctrl_reg;

	return (BF_NONE);
}

/*
 * Gather information about the error into an async_flt structure, and then
 * enqueue the error for reporting and processing and panic.
 */
static uint_t
sysio_ue_intr(struct sbus_soft_state *softsp)
{
	volatile uint64_t t_afsr;
	volatile uint64_t t_afar;
	volatile uint64_t *ue_reg, *afar_reg, *clear_reg;
	struct async_flt ecc;
	uint64_t offset;

	/*
	 * Disable all further sbus errors, for this sbus instance, for
	 * what is guaranteed to be a fatal error. And grab any other cpus.
	 */
	(void) sysio_dis_err(softsp);		/* disabled sysio errors */

	/*
	 * Then read and clear the afsr/afar and clear interrupt regs.
	 */
	ue_reg = (uint64_t *)softsp->sysio_ue_reg;
	t_afsr = *ue_reg;
	afar_reg = (uint64_t *)ue_reg + 1;
	t_afar = *afar_reg;
	*ue_reg = t_afsr;

	clear_reg = (softsp->clr_intr_reg + UE_ECC_CLEAR);
	*clear_reg = 0;

	/*
	 * The AFSR DW_OFFSET field contains the offset of the doubleword with
	 * the ECC error relative to the 64-byte aligned PA.  We multiply by 8
	 * to convert to a byte offset, and then add this to flt_addr.
	 */
	offset = ((t_afsr & SB_UE_AFSR_OFF) >> SB_UE_DW_SHIFT) * 8;

	bzero(&ecc, sizeof (ecc));
	ecc.flt_id = gethrtime();
	ecc.flt_stat = t_afsr;
	ecc.flt_addr = P2ALIGN(t_afar, 64) + offset;
	ecc.flt_func = sysio_log_ue_err;
	ecc.flt_bus_id = softsp->upa_id;
	ecc.flt_inst = ddi_get_instance(softsp->dip);
	ecc.flt_status = ECC_IOBUS;
	ecc.flt_in_memory = (pf_is_memory(t_afar >> MMU_PAGESHIFT)) ? 1: 0;
	ecc.flt_class = BUS_FAULT;
	ecc.flt_panic = (debug_sysio_errs == 0);

	errorq_dispatch(ue_queue, &ecc, sizeof (ecc), ecc.flt_panic);

	/*
	 * If the UE is in memory and fatal, save the fault info so the
	 * panic code will know to check for copyback errors.
	 */
	if (ecc.flt_panic && ecc.flt_in_memory)
		panic_aflt = ecc;

	/*
	 * We must also check for other bus UE errors, and panic if
	 * any fatal ones are detected at this point.
	 */
	if (bus_func_invoke(BF_TYPE_UE) == BF_FATAL)
		ecc.flt_panic = 1;

	if (ecc.flt_panic)
		cmn_err(CE_PANIC, "Fatal Sbus%d UE Error", ecc.flt_inst);

	return (DDI_INTR_CLAIMED);
}

/*
 * callback logging function from the common error handling code
 */
static void
sysio_log_ue_err(struct async_flt *ecc, char *unum)
{
	uint64_t t_afsr = ecc->flt_stat;
	uint64_t t_afar = ecc->flt_addr;

	ushort_t id = ecc->flt_bus_id;
	ushort_t inst = ecc->flt_inst;

	if (t_afsr & SB_UE_AFSR_P_PIO) {
		cmn_err(CE_WARN, "SBus%d UE Primary Error from PIO: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}
	if (t_afsr & SB_UE_AFSR_P_DRD) {
		cmn_err(CE_WARN, "SBus%d UE Primary Error DMA read: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr & SB_UE_AFSR_P_DWR) {
		cmn_err(CE_WARN, "SBus%d UE Primary Error DVMA write: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	/*
	 * We should never hit the secondary error panics.
	 */
	if (t_afsr & SB_UE_AFSR_S_PIO) {
		cmn_err(CE_WARN, "SBus%d UE Secondary Error from PIO: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}
	if (t_afsr & SB_UE_AFSR_S_DRD) {
		cmn_err(CE_WARN, "SBus%d UE Secondary Error DMA read: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr & SB_UE_AFSR_S_DWR) {
		cmn_err(CE_WARN, "SBus%d UE Secondary  Error DMA write: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}

	if ((debug_sysio_errs) || (aft_verbose)) {
		(void) read_ecc_data(ecc, 1, 0);
		cmn_err(CE_CONT, "\tOffset 0x%x, Size %d, UPA MID 0x%x\n",
		    (uint32_t)((t_afsr & SB_UE_AFSR_OFF) >> SB_UE_DW_SHIFT),
		    (uint32_t)((t_afsr & SB_UE_AFSR_SIZE) >> SB_UE_SIZE_SHIFT),
		    (uint32_t)((t_afsr & SB_UE_AFSR_MID) >> SB_UE_MID_SHIFT));
	}
}

/*
 * gather the information about the error, plus a pointer to
 * the callback logging function, and call the generic ce_error handler.
 */
static uint_t
sysio_ce_intr(struct sbus_soft_state *softsp)
{
	volatile uint64_t t_afsr;
	volatile uint64_t t_afar;
	volatile uint64_t *afar_reg, *clear_reg, *ce_reg;
	struct async_flt ecc;
	uint64_t offset;

	ce_reg = (uint64_t *)softsp->sysio_ce_reg;
	t_afsr = *ce_reg;
	afar_reg = (uint64_t *)ce_reg + 1;
	t_afar = *afar_reg;
	*ce_reg = t_afsr;

	clear_reg = (softsp->clr_intr_reg + CE_ECC_CLEAR);
	*clear_reg = 0;

	/*
	 * The AFSR DW_OFFSET field contains the offset of the doubleword with
	 * the ECC error relative to the 64-byte aligned PA.  We multiply by 8
	 * to convert to a byte offset, and then add this to flt_addr.
	 */
	offset = ((t_afsr & SB_UE_AFSR_OFF) >> SB_UE_DW_SHIFT) * 8;

	bzero(&ecc, sizeof (ecc));
	ecc.flt_id = gethrtime();
	ecc.flt_stat = t_afsr;
	ecc.flt_addr = P2ALIGN(t_afar, 64) + offset;
	ecc.flt_func = sysio_log_ce_err;
	ecc.flt_bus_id = softsp->upa_id;
	ecc.flt_inst = ddi_get_instance(softsp->dip);
	ecc.flt_status = ECC_IOBUS;

	ecc.flt_synd = (ushort_t)((t_afsr & SB_CE_AFSR_SYND) >>
	    SB_CE_SYND_SHIFT);

	ecc.flt_in_memory = (pf_is_memory(t_afar >> MMU_PAGESHIFT)) ? 1: 0;
	ecc.flt_class = BUS_FAULT;

	ce_scrub(&ecc);
	errorq_dispatch(ce_queue, &ecc, sizeof (ecc), ERRORQ_ASYNC);

	return (DDI_INTR_CLAIMED);
}

/*
 * callback logging function from the common error handling code
 */
static void
sysio_log_ce_err(struct async_flt *ecc, char *unum)
{
	uint64_t t_afsr = ecc->flt_stat;
	uint64_t t_afar = ecc->flt_addr;
	ushort_t id = ecc->flt_bus_id;
	ushort_t inst = ecc->flt_inst;
	int ce_verbose = ce_verbose_memory;
	char *syndrome_str = "!\tSyndrome 0x%x, Offset 0x%x, Size %d, "
	    "UPA MID 0x%x\n";

	if ((!ce_verbose_memory) && (!debug_sysio_errs))
		return;

	if (t_afsr & SB_CE_AFSR_P_PIO) {
		char *fmtstr = "!SBus%d CE Primary Error from PIO: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d\n";

		if ((debug_sysio_errs) || (ce_verbose > 1))
			fmtstr++;

		cmn_err(CE_CONT, fmtstr, inst, (uint32_t)(t_afsr>>32),
		    (uint32_t)t_afsr, (uint32_t)(t_afar>>32),
		    (uint32_t)t_afar, id);
	}
	if (t_afsr & SB_CE_AFSR_P_DRD) {
		char *fmtstr = "!SBus%d CE Primary Error DMA read: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n";

		if ((debug_sysio_errs) || (ce_verbose > 1))
			fmtstr++;

		cmn_err(CE_CONT, fmtstr, inst, (uint32_t)(t_afsr>>32),
		    (uint32_t)t_afsr, (uint32_t)(t_afar>>32), (uint32_t)t_afar,
		    unum, id);
	}
	if (t_afsr & SB_CE_AFSR_P_DWR) {
		char *fmtstr = "!SBus%d CE Primary Error DMA write: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s Id %d\n";

		if ((debug_sysio_errs) || (ce_verbose > 1))
			fmtstr++;

		cmn_err(CE_CONT, fmtstr, inst, (uint32_t)(t_afsr>>32),
		    (uint32_t)t_afsr, (uint32_t)(t_afar>>32), (uint32_t)t_afar,
		    unum, id);
	}

	if (t_afsr & SB_CE_AFSR_S_PIO) {
		char *fmtstr = "!SBus%d CE Secondary Error from PIO: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d\n";

		if ((debug_sysio_errs) || (ce_verbose > 1))
			fmtstr++;

		cmn_err(CE_CONT, fmtstr, inst, (uint32_t)(t_afsr>>32),
		    (uint32_t)t_afsr, (uint32_t)(t_afar>>32), (uint32_t)t_afar,
		    id);
	}
	if (t_afsr & SB_CE_AFSR_S_DRD) {
		char *fmtstr = "!SBus%d CE Secondary Error DMA read: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n";

		if ((debug_sysio_errs) || (ce_verbose > 1))
			fmtstr++;

		cmn_err(CE_CONT, fmtstr, inst, (uint32_t)(t_afsr>>32),
		    (uint32_t)t_afsr, (uint32_t)(t_afar>>32), (uint32_t)t_afar,
		    unum, id);
	}
	if (t_afsr & SB_CE_AFSR_S_DWR) {
		char *fmtstr = "!SBus%d CE Secondary Error DMA write: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n";

		if ((debug_sysio_errs) || (ce_verbose > 1))
			fmtstr++;

		cmn_err(CE_CONT, fmtstr,
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}

	if ((debug_sysio_errs) || (ce_verbose > 1))
		syndrome_str++;

	cmn_err(CE_CONT, syndrome_str,
	    (uint32_t)((t_afsr & SB_CE_AFSR_SYND) >> SB_CE_SYND_SHIFT),
	    (uint32_t)((t_afsr & SB_CE_AFSR_OFF) >> SB_CE_OFFSET_SHIFT),
	    (uint32_t)((t_afsr & SB_CE_AFSR_SIZE) >> SB_CE_SIZE_SHIFT),
	    (uint32_t)((t_afsr & SB_CE_AFSR_MID) >> SB_CE_MID_SHIFT));
}

static uint_t
sbus_err_intr(struct sbus_soft_state *softsp)
{
	volatile uint64_t t_afsr;
	volatile uint64_t t_afar;
	ushort_t id, inst;
	int cleared = 0;
	volatile uint64_t *afar_reg;
	on_trap_data_t *otp = softsp->ontrap_data;

	t_afsr = *softsp->sbus_err_reg;
	afar_reg = (uint64_t *)softsp->sbus_err_reg + 1;
	t_afar = *afar_reg;

	if (otp == NULL || !(otp->ot_prot & OT_DATA_ACCESS)) {
		sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
		cleared = 1;
	}

	id = (ushort_t)softsp->upa_id;
	inst = (ushort_t)ddi_get_instance(softsp->dip);

	if (debug_sysio_errs) {
		if (otp != NULL && (otp->ot_prot & OT_DATA_ACCESS))
			otp->ot_trap |= OT_DATA_ACCESS;
		if (!cleared)
			sbus_clear_intr(softsp, (uint64_t *)&t_afsr);

		cmn_err(CE_CONT, "SBus%d Error: AFSR 0x%08x.%08x "
			"AFAR 0x%08x.%08x Id %d\n",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);

		debug_enter("sbus_err_intr");
	} else {
		sbus_log_error(softsp, (uint64_t *)&t_afsr,
		    (uint64_t *)&t_afar, id, inst, cleared, otp);
	}
	if (!cleared) {
		sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
	}

	return (DDI_INTR_CLAIMED);
}

static void
sbus_clear_intr(struct sbus_soft_state *softsp, uint64_t *pafsr)
{
	volatile uint64_t *clear_reg;

	*softsp->sbus_err_reg = *pafsr;
	clear_reg = (softsp->clr_intr_reg + SBUS_ERR_CLEAR);
	*clear_reg = 0;
}

static void
sbus_log_error(struct sbus_soft_state *softsp, uint64_t *pafsr, uint64_t *pafar,
    ushort_t id, ushort_t inst, int cleared, on_trap_data_t *otp)
{
	uint64_t t_afsr;
	uint64_t t_afar;
	int level = CE_WARN;

	t_afsr = *pafsr;
	t_afar = *pafar;
	if (t_afsr & SB_AFSR_P_LE) {
		if (!cleared)
			sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
		cmn_err(CE_PANIC, "SBus%d Primary Error Late PIO: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}
	if (t_afsr & SB_AFSR_P_TO) {
		if (otp != NULL && (otp->ot_prot & OT_DATA_ACCESS)) {
			otp->ot_trap |= OT_DATA_ACCESS;
			return;
		}
		if (sbus_check_bto(softsp)) {
			if (!cleared)
				sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
			level = CE_PANIC;
		}
		cmn_err(level, "SBus%d Primary Error Timeout: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}
	if (t_afsr & SB_AFSR_P_BERR) {
		if (otp != NULL && (otp->ot_prot & OT_DATA_ACCESS)) {
			otp->ot_trap |= OT_DATA_ACCESS;
			return;
		}
		if (sbus_check_bto(softsp)) {
			if (!cleared)
				sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
			level = CE_PANIC;
		}
		cmn_err(level, "SBus%d Primary Error Bus Error: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d\n",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}

	if (t_afsr & SB_AFSR_S_LE) {
		if (!cleared)
			sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
		cmn_err(CE_PANIC, "SBus%d Secondary Late PIO Error: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}
	if (t_afsr & SB_AFSR_S_TO) {
		if (sbus_check_bto(softsp)) {
			if (!cleared)
				sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
			level = CE_PANIC;
		}
		cmn_err(level, "SBus%d Secondary Timeout Error: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}
	if (t_afsr & SB_AFSR_S_BERR) {
		if (sbus_check_bto(softsp)) {
			if (!cleared)
				sbus_clear_intr(softsp, (uint64_t *)&t_afsr);
			level = CE_PANIC;
		}
		cmn_err(level, "SBus%d Secondary Bus Error: "
			"AFSR 0x%08x.%08x AFAR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
			(uint32_t)(t_afar>>32), (uint32_t)t_afar, id);
	}
}


static int
sbus_check_bto(struct sbus_soft_state *softsp)
{
	hrtime_t now = gethrtime();		/* high PIL safe */
	hrtime_t diff = now - softsp->bto_timestamp;

	if (diff > ((hrtime_t)bto_secs * NANOSEC) || diff < 0LL) {
		/*
		 * Reset error counter as this bus error has occurred
		 * after more than bto_secs duration.
		 */
		softsp->bto_timestamp = now;
		softsp->bto_ctr = 0;
	}
	if (softsp->bto_ctr++ >= bto_cnt)
		return (1);
	return (0);
}

static uint_t
sbus_ctrl_ecc_err(struct sbus_soft_state *softsp)
{
	uint64_t t_sb_csr;
	ushort_t id, inst;

	t_sb_csr = *softsp->sbus_ctrl_reg;
	id = (ushort_t)softsp->upa_id;
	inst = (ushort_t)ddi_get_instance(softsp->dip);

	if (debug_sysio_errs) {
		cmn_err(CE_CONT, "sbus_ctrl_ecc_error: SBus%d Control Reg "
		    "0x%016llx Id %d\n", inst, (u_longlong_t)t_sb_csr, id);
	}

	if (t_sb_csr & (SB_CSR_DPERR_S14|SB_CSR_DPERR_S13|SB_CSR_DPERR_S3|
	    SB_CSR_DPERR_S2|SB_CSR_DPERR_S1|SB_CSR_DPERR_S0|SB_CSR_PIO_PERRS)) {
		struct async_flt aflt;

		*softsp->sbus_ctrl_reg = t_sb_csr; /* clear error bits */

		bzero(&aflt, sizeof (aflt));
		aflt.flt_id = gethrtime();
		aflt.flt_stat = t_sb_csr;
		aflt.flt_func = sbus_log_csr_error;
		aflt.flt_bus_id = id;
		aflt.flt_inst = inst;
		aflt.flt_status = ECC_IOBUS;
		aflt.flt_class = BUS_FAULT;
		aflt.flt_panic = 1;

		errorq_dispatch(ue_queue, &aflt, sizeof (aflt), aflt.flt_panic);
		return (BF_FATAL);
	}

	return (BF_NONE);
}

/*ARGSUSED*/
static void
sbus_log_csr_error(struct async_flt *aflt, char *unum)
{
	uint64_t t_sb_csr = aflt->flt_stat;
	uint_t id = aflt->flt_bus_id;
	uint_t inst = aflt->flt_inst;

	/*
	 * Print out SBus error information.
	 */
	if (t_sb_csr & SB_CSR_DPERR_S14) {
		cmn_err(CE_WARN,
		"SBus%d Slot 14 DVMA Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_DPERR_S13) {
		cmn_err(CE_WARN,
		"SBus%d Slot 13 DVMA Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_DPERR_S3) {
		cmn_err(CE_WARN,
		"SBus%d Slot 3 DVMA Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_DPERR_S2) {
		cmn_err(CE_WARN,
		"SBus%d Slot 2 DVMA Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_DPERR_S1) {
		cmn_err(CE_WARN,
		"SBus%d Slot 1 DVMA Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_DPERR_S0) {
		cmn_err(CE_WARN,
		"SBus%d Slot 0 DVMA Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_PPERR_S15) {
		cmn_err(CE_WARN,
		"SBus%d Slot 15 PIO Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_PPERR_S14) {
		cmn_err(CE_WARN,
		"SBus%d Slot 14 PIO Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_PPERR_S13) {
		cmn_err(CE_WARN,
		"SBus%d Slot 13 PIO Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_PPERR_S3) {
		cmn_err(CE_WARN,
		"SBus%d Slot 3 PIO Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_PPERR_S2) {
		cmn_err(CE_WARN,
		"SBus%d Slot 2 PIO Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_PPERR_S1) {
		cmn_err(CE_WARN,
		"SBus%d Slot 1 PIO Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
	if (t_sb_csr & SB_CSR_PPERR_S0) {
		cmn_err(CE_WARN,
		"SBus%d Slot 0 PIO Parity Error: AFSR 0x%08x.%08x Id %d",
			inst, (uint32_t)(t_sb_csr>>32), (uint32_t)t_sb_csr, id);
	}
}

/*
 * Sysio Thermal Warning interrupt handler
 */
static uint_t
sysio_thermal_warn_intr(struct sbus_soft_state *softsp)
{
	volatile uint64_t *clear_reg;
	volatile uint64_t tmp_mondo_vec;
	volatile uint64_t *mondo_vec_reg;
	const char thermal_warn_msg[] =
	    "Severe over-temperature condition detected!";

	/*
	 * Take off the Thermal Warning interrupt and
	 * remove its interrupt handler.
	 */
	mondo_vec_reg = (softsp->intr_mapping_reg + THERMAL_MAPREG);
	tmp_mondo_vec = *mondo_vec_reg;
	tmp_mondo_vec &= ~INTERRUPT_VALID;
	*mondo_vec_reg = tmp_mondo_vec;

	ddi_remove_intr(softsp->dip, 4, NULL);

	clear_reg = (softsp->clr_intr_reg + THERMAL_CLEAR);
	*clear_reg = 0;

	if (oven_test) {
		cmn_err(CE_NOTE, "OVEN TEST: %s", thermal_warn_msg);
		return (DDI_INTR_CLAIMED);
	}

	cmn_err(CE_WARN, "%s", thermal_warn_msg);
	cmn_err(CE_WARN, "Powering down...");

	do_shutdown();

	/*
	 * just in case do_shutdown() fails
	 */
	(void) timeout((void(*)(void *))power_down, NULL,
	    thermal_powerdown_delay * hz);

	return (DDI_INTR_CLAIMED);
}
