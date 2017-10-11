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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2018 Joyent, Inc.
 * Copyright (c) 2016, 2017 by Delphix. All rights reserved.
 */

/*
 * PSMI 1.1 extensions are supported only in 2.6 and later versions.
 * PSMI 1.2 extensions are supported only in 2.7 and later versions.
 * PSMI 1.3 and 1.4 extensions are supported in Solaris 10.
 * PSMI 1.5 extensions are supported in Solaris Nevada.
 * PSMI 1.6 extensions are supported in Solaris Nevada.
 * PSMI 1.7 extensions are supported in Solaris Nevada.
 */
#define	PSMI_1_7

#include <sys/processor.h>
#include <sys/time.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>
#include <sys/cram.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/psm_common.h>
#include <sys/apic.h>
#include <sys/pit.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/promif.h>
#include <sys/x86_archext.h>
#include <sys/cpc_impl.h>
#include <sys/uadmin.h>
#include <sys/panic.h>
#include <sys/debug.h>
#include <sys/archsystm.h>
#include <sys/trap.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/rm_platter.h>
#include <sys/privregs.h>
#include <sys/note.h>
#include <sys/pci_intr_lib.h>
#include <sys/spl.h>
#include <sys/clock.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/x_call.h>
#include <sys/reboot.h>
#include <sys/hpet.h>
#include <sys/apic_common.h>
#include <sys/apic_timer.h>

static void	apic_record_ioapic_rdt(void *intrmap_private,
		    ioapic_rdt_t *irdt);
static void	apic_record_msi(void *intrmap_private, msi_regs_t *mregs);

/*
 * Common routines between pcplusmp & apix (taken from apic.c).
 */

int	apic_clkinit(int);
hrtime_t apic_gethrtime(void);
void	apic_send_ipi(int, int);
void	apic_set_idlecpu(processorid_t);
void	apic_unset_idlecpu(processorid_t);
void	apic_shutdown(int, int);
void	apic_preshutdown(int, int);
processorid_t	apic_get_next_processorid(processorid_t);

hrtime_t apic_gettime();

enum apic_ioapic_method_type apix_mul_ioapic_method = APIC_MUL_IOAPIC_PCPLUSMP;

/* Now the ones for Dynamic Interrupt distribution */
int	apic_enable_dynamic_migration = 0;

/* maximum loop count when sending Start IPIs. */
int apic_sipi_max_loop_count = 0x1000;

/*
 * These variables are frequently accessed in apic_intr_enter(),
 * apic_intr_exit and apic_setspl, so group them together
 */
volatile uint32_t *apicadr =  NULL;	/* virtual addr of local APIC	*/
int apic_setspl_delay = 1;		/* apic_setspl - delay enable	*/
int apic_clkvect;

/* vector at which error interrupts come in */
int apic_errvect;
int apic_enable_error_intr = 1;
int apic_error_display_delay = 100;

/* vector at which performance counter overflow interrupts come in */
int apic_cpcovf_vect;
int apic_enable_cpcovf_intr = 1;

/* vector at which CMCI interrupts come in */
int apic_cmci_vect;
extern int cmi_enable_cmci;
extern void cmi_cmci_trap(void);

kmutex_t cmci_cpu_setup_lock;	/* protects cmci_cpu_setup_registered */
int cmci_cpu_setup_registered;

lock_t apic_mode_switch_lock;

int apic_pir_vect;

/*
 * Patchable global variables.
 */
int	apic_forceload = 0;

int	apic_coarse_hrtime = 1;		/* 0 - use accurate slow gethrtime() */

int	apic_flat_model = 0;		/* 0 - clustered. 1 - flat */
int	apic_panic_on_nmi = 0;
int	apic_panic_on_apic_error = 0;

int	apic_verbose = 0;	/* 0x1ff */

#ifdef DEBUG
int	apic_debug = 0;
int	apic_restrict_vector = 0;

int	apic_debug_msgbuf[APIC_DEBUG_MSGBUFSIZE];
int	apic_debug_msgbufindex = 0;

#endif /* DEBUG */

uint_t apic_nticks = 0;
uint_t apic_skipped_redistribute = 0;

uint_t last_count_read = 0;
lock_t	apic_gethrtime_lock;
volatile int	apic_hrtime_stamp = 0;
volatile hrtime_t apic_nsec_since_boot = 0;

static	hrtime_t	apic_last_hrtime = 0;
int		apic_hrtime_error = 0;
int		apic_remote_hrterr = 0;
int		apic_num_nmis = 0;
int		apic_apic_error = 0;
int		apic_num_apic_errors = 0;
int		apic_num_cksum_errors = 0;

int	apic_error = 0;

static	int	apic_cmos_ssb_set = 0;

/* use to make sure only one cpu handles the nmi */
lock_t	apic_nmi_lock;
/* use to make sure only one cpu handles the error interrupt */
lock_t	apic_error_lock;

static	struct {
	uchar_t	cntl;
	uchar_t	data;
} aspen_bmc[] = {
	{ CC_SMS_WR_START,	0x18 },		/* NetFn/LUN */
	{ CC_SMS_WR_NEXT,	0x24 },		/* Cmd SET_WATCHDOG_TIMER */
	{ CC_SMS_WR_NEXT,	0x84 },		/* DataByte 1: SMS/OS no log */
	{ CC_SMS_WR_NEXT,	0x2 },		/* DataByte 2: Power Down */
	{ CC_SMS_WR_NEXT,	0x0 },		/* DataByte 3: no pre-timeout */
	{ CC_SMS_WR_NEXT,	0x0 },		/* DataByte 4: timer expir. */
	{ CC_SMS_WR_NEXT,	0xa },		/* DataByte 5: init countdown */
	{ CC_SMS_WR_END,	0x0 },		/* DataByte 6: init countdown */

	{ CC_SMS_WR_START,	0x18 },		/* NetFn/LUN */
	{ CC_SMS_WR_END,	0x22 }		/* Cmd RESET_WATCHDOG_TIMER */
};

static	struct {
	int	port;
	uchar_t	data;
} sitka_bmc[] = {
	{ SMS_COMMAND_REGISTER,	SMS_WRITE_START },
	{ SMS_DATA_REGISTER,	0x18 },		/* NetFn/LUN */
	{ SMS_DATA_REGISTER,	0x24 },		/* Cmd SET_WATCHDOG_TIMER */
	{ SMS_DATA_REGISTER,	0x84 },		/* DataByte 1: SMS/OS no log */
	{ SMS_DATA_REGISTER,	0x2 },		/* DataByte 2: Power Down */
	{ SMS_DATA_REGISTER,	0x0 },		/* DataByte 3: no pre-timeout */
	{ SMS_DATA_REGISTER,	0x0 },		/* DataByte 4: timer expir. */
	{ SMS_DATA_REGISTER,	0xa },		/* DataByte 5: init countdown */
	{ SMS_COMMAND_REGISTER,	SMS_WRITE_END },
	{ SMS_DATA_REGISTER,	0x0 },		/* DataByte 6: init countdown */

	{ SMS_COMMAND_REGISTER,	SMS_WRITE_START },
	{ SMS_DATA_REGISTER,	0x18 },		/* NetFn/LUN */
	{ SMS_COMMAND_REGISTER,	SMS_WRITE_END },
	{ SMS_DATA_REGISTER,	0x22 }		/* Cmd RESET_WATCHDOG_TIMER */
};

/* Patchable global variables. */
int		apic_kmdb_on_nmi = 0;		/* 0 - no, 1 - yes enter kmdb */
uint32_t	apic_divide_reg_init = 0;	/* 0 - divide by 2 */

/* default apic ops without interrupt remapping */
static apic_intrmap_ops_t apic_nointrmap_ops = {
	(int (*)(int))return_instr,
	(void (*)(int))return_instr,
	(void (*)(void **, dev_info_t *, uint16_t, int, uchar_t))return_instr,
	(void (*)(void *, void *, uint16_t, int))return_instr,
	(void (*)(void **))return_instr,
	apic_record_ioapic_rdt,
	apic_record_msi,
};

apic_intrmap_ops_t *apic_vt_ops = &apic_nointrmap_ops;
apic_cpus_info_t	*apic_cpus = NULL;
cpuset_t	apic_cpumask;
uint_t		apic_picinit_called;

/* Flag to indicate that we need to shut down all processors */
static uint_t	apic_shutdown_processors;

/*
 * Probe the ioapic method for apix module. Called in apic_probe_common()
 */
int
apic_ioapic_method_probe()
{
	if (apix_enable == 0)
		return (PSM_SUCCESS);

	/*
	 * Set IOAPIC EOI handling method. The priority from low to high is:
	 *	1. IOxAPIC: with EOI register
	 *	2. IOMMU interrupt mapping
	 *	3. Mask-Before-EOI method for systems without boot
	 *	interrupt routing, such as systems with only one IOAPIC;
	 *	NVIDIA CK8-04/MCP55 systems; systems with bridge solution
	 *	which disables the boot interrupt routing already.
	 *	4. Directed EOI
	 */
	if (apic_io_ver[0] >= 0x20)
		apix_mul_ioapic_method = APIC_MUL_IOAPIC_IOXAPIC;
	if ((apic_io_max == 1) || (apic_nvidia_io_max == apic_io_max))
		apix_mul_ioapic_method = APIC_MUL_IOAPIC_MASK;
	if (apic_directed_EOI_supported())
		apix_mul_ioapic_method = APIC_MUL_IOAPIC_DEOI;

	/* fall back to pcplusmp */
	if (apix_mul_ioapic_method == APIC_MUL_IOAPIC_PCPLUSMP) {
		/* make sure apix is after pcplusmp in /etc/mach */
		apix_enable = 0; /* go ahead with pcplusmp install next */
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

/*
 * handler for APIC Error interrupt. Just print a warning and continue
 */
int
apic_error_intr()
{
	uint_t	error0, error1, error;
	uint_t	i;

	/*
	 * We need to write before read as per 7.4.17 of system prog manual.
	 * We do both and or the results to be safe
	 */
	error0 = apic_reg_ops->apic_read(APIC_ERROR_STATUS);
	apic_reg_ops->apic_write(APIC_ERROR_STATUS, 0);
	error1 = apic_reg_ops->apic_read(APIC_ERROR_STATUS);
	error = error0 | error1;

	/*
	 * Clear the APIC error status (do this on all cpus that enter here)
	 * (two writes are required due to the semantics of accessing the
	 * error status register.)
	 */
	apic_reg_ops->apic_write(APIC_ERROR_STATUS, 0);
	apic_reg_ops->apic_write(APIC_ERROR_STATUS, 0);

	/*
	 * Prevent more than 1 CPU from handling error interrupt causing
	 * double printing (interleave of characters from multiple
	 * CPU's when using prom_printf)
	 */
	if (lock_try(&apic_error_lock) == 0)
		return (error ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
	if (error) {
#if	DEBUG
		if (apic_debug)
			debug_enter("pcplusmp: APIC Error interrupt received");
#endif /* DEBUG */
		if (apic_panic_on_apic_error)
			cmn_err(CE_PANIC,
			    "APIC Error interrupt on CPU %d. Status = %x",
			    psm_get_cpu_id(), error);
		else {
			if ((error & ~APIC_CS_ERRORS) == 0) {
				/* cksum error only */
				apic_error |= APIC_ERR_APIC_ERROR;
				apic_apic_error |= error;
				apic_num_apic_errors++;
				apic_num_cksum_errors++;
			} else {
				/*
				 * prom_printf is the best shot we have of
				 * something which is problem free from
				 * high level/NMI type of interrupts
				 */
				prom_printf("APIC Error interrupt on CPU %d. "
				    "Status 0 = %x, Status 1 = %x\n",
				    psm_get_cpu_id(), error0, error1);
				apic_error |= APIC_ERR_APIC_ERROR;
				apic_apic_error |= error;
				apic_num_apic_errors++;
				for (i = 0; i < apic_error_display_delay; i++) {
					tenmicrosec();
				}
				/*
				 * provide more delay next time limited to
				 * roughly 1 clock tick time
				 */
				if (apic_error_display_delay < 500)
					apic_error_display_delay *= 2;
			}
		}
		lock_clear(&apic_error_lock);
		return (DDI_INTR_CLAIMED);
	} else {
		lock_clear(&apic_error_lock);
		return (DDI_INTR_UNCLAIMED);
	}
}

/*
 * Turn off the mask bit in the performance counter Local Vector Table entry.
 */
void
apic_cpcovf_mask_clear(void)
{
	apic_reg_ops->apic_write(APIC_PCINT_VECT,
	    (apic_reg_ops->apic_read(APIC_PCINT_VECT) & ~APIC_LVT_MASK));
}

/*ARGSUSED*/
static int
apic_cmci_enable(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	apic_reg_ops->apic_write(APIC_CMCI_VECT, apic_cmci_vect);
	return (0);
}

/*ARGSUSED*/
static int
apic_cmci_disable(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	apic_reg_ops->apic_write(APIC_CMCI_VECT, apic_cmci_vect | AV_MASK);
	return (0);
}

/*ARGSUSED*/
int
cmci_cpu_setup(cpu_setup_t what, int cpuid, void *arg)
{
	cpuset_t	cpu_set;

	CPUSET_ONLY(cpu_set, cpuid);

	switch (what) {
		case CPU_ON:
			xc_call(NULL, NULL, NULL, CPUSET2BV(cpu_set),
			    (xc_func_t)apic_cmci_enable);
			break;

		case CPU_OFF:
			xc_call(NULL, NULL, NULL, CPUSET2BV(cpu_set),
			    (xc_func_t)apic_cmci_disable);
			break;

		default:
			break;
	}

	return (0);
}

static void
apic_disable_local_apic(void)
{
	apic_reg_ops->apic_write_task_reg(APIC_MASK_ALL);
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER, AV_MASK);

	/* local intr reg 0 */
	apic_reg_ops->apic_write(APIC_INT_VECT0, AV_MASK);

	/* disable NMI */
	apic_reg_ops->apic_write(APIC_INT_VECT1, AV_MASK);

	/* and error interrupt */
	apic_reg_ops->apic_write(APIC_ERR_VECT, AV_MASK);

	/* and perf counter intr */
	apic_reg_ops->apic_write(APIC_PCINT_VECT, AV_MASK);

	apic_reg_ops->apic_write(APIC_SPUR_INT_REG, APIC_SPUR_INTR);
}

static void
apic_cpu_send_SIPI(processorid_t cpun, boolean_t start)
{
	int		loop_count;
	uint32_t	vector;
	uint_t		apicid;
	ulong_t		iflag;

	apicid =  apic_cpus[cpun].aci_local_id;

	/*
	 * Interrupts on current CPU will be disabled during the
	 * steps in order to avoid unwanted side effects from
	 * executing interrupt handlers on a problematic BIOS.
	 */
	iflag = intr_clear();

	if (start) {
		outb(CMOS_ADDR, SSB);
		outb(CMOS_DATA, BIOS_SHUTDOWN);
	}

	/*
	 * According to X2APIC specification in section '2.3.5.1' of
	 * Interrupt Command Register Semantics, the semantics of
	 * programming the Interrupt Command Register to dispatch an interrupt
	 * is simplified. A single MSR write to the 64-bit ICR is required
	 * for dispatching an interrupt. Specifically, with the 64-bit MSR
	 * interface to ICR, system software is not required to check the
	 * status of the delivery status bit prior to writing to the ICR
	 * to send an IPI. With the removal of the Delivery Status bit,
	 * system software no longer has a reason to read the ICR. It remains
	 * readable only to aid in debugging.
	 */
#ifdef	DEBUG
	APIC_AV_PENDING_SET();
#else
	if (apic_mode == LOCAL_APIC) {
		APIC_AV_PENDING_SET();
	}
#endif /* DEBUG */

	/* for integrated - make sure there is one INIT IPI in buffer */
	/* for external - it will wake up the cpu */
	apic_reg_ops->apic_write_int_cmd(apicid, AV_ASSERT | AV_RESET);

	/* If only 1 CPU is installed, PENDING bit will not go low */
	for (loop_count = apic_sipi_max_loop_count; loop_count; loop_count--) {
		if (apic_mode == LOCAL_APIC &&
		    apic_reg_ops->apic_read(APIC_INT_CMD1) & AV_PENDING)
			apic_ret();
		else
			break;
	}

	apic_reg_ops->apic_write_int_cmd(apicid, AV_DEASSERT | AV_RESET);
	drv_usecwait(20000);		/* 20 milli sec */

	if (apic_cpus[cpun].aci_local_ver >= APIC_INTEGRATED_VERS) {
		/* integrated apic */

		vector = (rm_platter_pa >> MMU_PAGESHIFT) &
		    (APIC_VECTOR_MASK | APIC_IPL_MASK);

		/* to offset the INIT IPI queue up in the buffer */
		apic_reg_ops->apic_write_int_cmd(apicid, vector | AV_STARTUP);
		drv_usecwait(200);		/* 20 micro sec */

		/*
		 * send the second SIPI (Startup IPI) as recommended by Intel
		 * software development manual.
		 */
		apic_reg_ops->apic_write_int_cmd(apicid, vector | AV_STARTUP);
		drv_usecwait(200);	/* 20 micro sec */
	}

	intr_restore(iflag);
}

/*ARGSUSED1*/
int
apic_cpu_start(processorid_t cpun, caddr_t arg)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (!apic_cpu_in_range(cpun)) {
		return (EINVAL);
	}

	/*
	 * Switch to apic_common_send_ipi for safety during starting other CPUs.
	 */
	if (apic_mode == LOCAL_X2APIC) {
		apic_switch_ipi_callback(B_TRUE);
	}

	apic_cmos_ssb_set = 1;
	apic_cpu_send_SIPI(cpun, B_TRUE);

	return (0);
}

/*
 * Put CPU into halted state with interrupts disabled.
 */
/*ARGSUSED1*/
int
apic_cpu_stop(processorid_t cpun, caddr_t arg)
{
	int		rc;
	cpu_t		*cp;
	extern cpuset_t cpu_ready_set;
	extern void cpu_idle_intercept_cpu(cpu_t *cp);

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (!apic_cpu_in_range(cpun)) {
		return (EINVAL);
	}
	if (apic_cpus[cpun].aci_local_ver < APIC_INTEGRATED_VERS) {
		return (ENOTSUP);
	}

	cp = cpu_get(cpun);
	ASSERT(cp != NULL);
	ASSERT((cp->cpu_flags & CPU_OFFLINE) != 0);
	ASSERT((cp->cpu_flags & CPU_QUIESCED) != 0);
	ASSERT((cp->cpu_flags & CPU_ENABLE) == 0);

	/* Clear CPU_READY flag to disable cross calls. */
	cp->cpu_flags &= ~CPU_READY;
	CPUSET_ATOMIC_DEL(cpu_ready_set, cpun);
	rc = xc_flush_cpu(cp);
	if (rc != 0) {
		CPUSET_ATOMIC_ADD(cpu_ready_set, cpun);
		cp->cpu_flags |= CPU_READY;
		return (rc);
	}

	/* Intercept target CPU at a safe point before powering it off. */
	cpu_idle_intercept_cpu(cp);

	apic_cpu_send_SIPI(cpun, B_FALSE);
	cp->cpu_flags &= ~CPU_RUNNING;

	return (0);
}

int
apic_cpu_ops(psm_cpu_request_t *reqp)
{
	if (reqp == NULL) {
		return (EINVAL);
	}

	switch (reqp->pcr_cmd) {
	case PSM_CPU_ADD:
		return (apic_cpu_add(reqp));

	case PSM_CPU_REMOVE:
		return (apic_cpu_remove(reqp));

	case PSM_CPU_STOP:
		return (apic_cpu_stop(reqp->req.cpu_stop.cpuid,
		    reqp->req.cpu_stop.ctx));

	default:
		return (ENOTSUP);
	}
}

#ifdef	DEBUG
int	apic_break_on_cpu = 9;
int	apic_stretch_interrupts = 0;
int	apic_stretch_ISR = 1 << 3;	/* IPL of 3 matches nothing now */
#endif /* DEBUG */

/*
 * generates an interprocessor interrupt to another CPU. Any changes made to
 * this routine must be accompanied by similar changes to
 * apic_common_send_ipi().
 */
void
apic_send_ipi(int cpun, int ipl)
{
	int vector;
	ulong_t flag;

	vector = apic_resv_vector[ipl];

	ASSERT((vector >= APIC_BASE_VECT) && (vector <= APIC_SPUR_INTR));

	flag = intr_clear();

	APIC_AV_PENDING_SET();

	apic_reg_ops->apic_write_int_cmd(apic_cpus[cpun].aci_local_id,
	    vector);

	intr_restore(flag);
}

void
apic_send_pir_ipi(processorid_t cpun)
{
	const int vector = apic_pir_vect;
	ulong_t flag;

	ASSERT((vector >= APIC_BASE_VECT) && (vector <= APIC_SPUR_INTR));

	flag = intr_clear();

	/* Self-IPI for inducing PIR makes no sense. */
	if ((cpun != psm_get_cpu_id())) {
		APIC_AV_PENDING_SET();
		apic_reg_ops->apic_write_int_cmd(apic_cpus[cpun].aci_local_id,
		    vector);
	}

	intr_restore(flag);
}

int
apic_get_pir_ipivect(void)
{
	return (apic_pir_vect);
}

/*ARGSUSED*/
void
apic_set_idlecpu(processorid_t cpun)
{
}

/*ARGSUSED*/
void
apic_unset_idlecpu(processorid_t cpun)
{
}


void
apic_ret()
{
}

/*
 * If apic_coarse_time == 1, then apic_gettime() is used instead of
 * apic_gethrtime().  This is used for performance instead of accuracy.
 */

hrtime_t
apic_gettime()
{
	int old_hrtime_stamp;
	hrtime_t temp;

	/*
	 * In one-shot mode, we do not keep time, so if anyone
	 * calls psm_gettime() directly, we vector over to
	 * gethrtime().
	 * one-shot mode MUST NOT be enabled if this psm is the source of
	 * hrtime.
	 */

	if (apic_oneshot)
		return (gethrtime());


gettime_again:
	while ((old_hrtime_stamp = apic_hrtime_stamp) & 1)
		apic_ret();

	temp = apic_nsec_since_boot;

	if (apic_hrtime_stamp != old_hrtime_stamp) {	/* got an interrupt */
		goto gettime_again;
	}
	return (temp);
}

/*
 * Here we return the number of nanoseconds since booting.  Note every
 * clock interrupt increments apic_nsec_since_boot by the appropriate
 * amount.
 */
hrtime_t
apic_gethrtime(void)
{
	int curr_timeval, countval, elapsed_ticks;
	int old_hrtime_stamp, status;
	hrtime_t temp;
	uint32_t cpun;
	ulong_t oflags;

	/*
	 * In one-shot mode, we do not keep time, so if anyone
	 * calls psm_gethrtime() directly, we vector over to
	 * gethrtime().
	 * one-shot mode MUST NOT be enabled if this psm is the source of
	 * hrtime.
	 */

	if (apic_oneshot)
		return (gethrtime());

	oflags = intr_clear();	/* prevent migration */

	cpun = apic_reg_ops->apic_read(APIC_LID_REG);
	if (apic_mode == LOCAL_APIC)
		cpun >>= APIC_ID_BIT_OFFSET;

	lock_set(&apic_gethrtime_lock);

gethrtime_again:
	while ((old_hrtime_stamp = apic_hrtime_stamp) & 1)
		apic_ret();

	/*
	 * Check to see which CPU we are on.  Note the time is kept on
	 * the local APIC of CPU 0.  If on CPU 0, simply read the current
	 * counter.  If on another CPU, issue a remote read command to CPU 0.
	 */
	if (cpun == apic_cpus[0].aci_local_id) {
		countval = apic_reg_ops->apic_read(APIC_CURR_COUNT);
	} else {
#ifdef	DEBUG
		APIC_AV_PENDING_SET();
#else
		if (apic_mode == LOCAL_APIC)
			APIC_AV_PENDING_SET();
#endif /* DEBUG */

		apic_reg_ops->apic_write_int_cmd(
		    apic_cpus[0].aci_local_id, APIC_CURR_ADD | AV_REMOTE);

		while ((status = apic_reg_ops->apic_read(APIC_INT_CMD1))
		    & AV_READ_PENDING) {
			apic_ret();
		}

		if (status & AV_REMOTE_STATUS)	/* 1 = valid */
			countval = apic_reg_ops->apic_read(APIC_REMOTE_READ);
		else {	/* 0 = invalid */
			apic_remote_hrterr++;
			/*
			 * return last hrtime right now, will need more
			 * testing if change to retry
			 */
			temp = apic_last_hrtime;

			lock_clear(&apic_gethrtime_lock);

			intr_restore(oflags);

			return (temp);
		}
	}
	if (countval > last_count_read)
		countval = 0;
	else
		last_count_read = countval;

	elapsed_ticks = apic_hertz_count - countval;

	curr_timeval = APIC_TICKS_TO_NSECS(elapsed_ticks);
	temp = apic_nsec_since_boot + curr_timeval;

	if (apic_hrtime_stamp != old_hrtime_stamp) {	/* got an interrupt */
		/* we might have clobbered last_count_read. Restore it */
		last_count_read = apic_hertz_count;
		goto gethrtime_again;
	}

	if (temp < apic_last_hrtime) {
		/* return last hrtime if error occurs */
		apic_hrtime_error++;
		temp = apic_last_hrtime;
	}
	else
		apic_last_hrtime = temp;

	lock_clear(&apic_gethrtime_lock);
	intr_restore(oflags);

	return (temp);
}

/* apic NMI handler */
/*ARGSUSED*/
void
apic_nmi_intr(caddr_t arg, struct regs *rp)
{
	if (apic_shutdown_processors) {
		apic_disable_local_apic();
		return;
	}

	apic_error |= APIC_ERR_NMI;

	if (!lock_try(&apic_nmi_lock))
		return;
	apic_num_nmis++;

	if (apic_kmdb_on_nmi && psm_debugger()) {
		debug_enter("NMI received: entering kmdb\n");
	} else if (apic_panic_on_nmi) {
		/* Keep panic from entering kmdb. */
		nopanicdebug = 1;
		panic("NMI received\n");
	} else {
		/*
		 * prom_printf is the best shot we have of something which is
		 * problem free from high level/NMI type of interrupts
		 */
		prom_printf("NMI received\n");
	}

	lock_clear(&apic_nmi_lock);
}

processorid_t
apic_get_next_processorid(processorid_t cpu_id)
{

	int i;

	if (cpu_id == -1)
		return ((processorid_t)0);

	for (i = cpu_id + 1; i < NCPU; i++) {
		if (apic_cpu_in_range(i))
			return (i);
	}

	return ((processorid_t)-1);
}

int
apic_cpu_add(psm_cpu_request_t *reqp)
{
	int i, rv = 0;
	ulong_t iflag;
	boolean_t first = B_TRUE;
	uchar_t localver = 0;
	uint32_t localid, procid;
	processorid_t cpuid = (processorid_t)-1;
	mach_cpu_add_arg_t *ap;

	ASSERT(reqp != NULL);
	reqp->req.cpu_add.cpuid = (processorid_t)-1;

	/* Check whether CPU hotplug is supported. */
	if (!plat_dr_support_cpu() || apic_max_nproc == -1) {
		return (ENOTSUP);
	}

	ap = (mach_cpu_add_arg_t *)reqp->req.cpu_add.argp;
	switch (ap->type) {
	case MACH_CPU_ARG_LOCAL_APIC:
		localid = ap->arg.apic.apic_id;
		procid = ap->arg.apic.proc_id;
		if (localid >= 255 || procid > 255) {
			cmn_err(CE_WARN,
			    "!apic: apicid(%u) or procid(%u) is invalid.",
			    localid, procid);
			return (EINVAL);
		}
		break;

	case MACH_CPU_ARG_LOCAL_X2APIC:
		localid = ap->arg.apic.apic_id;
		procid = ap->arg.apic.proc_id;
		if (localid >= UINT32_MAX) {
			cmn_err(CE_WARN,
			    "!apic: x2apicid(%u) is invalid.", localid);
			return (EINVAL);
		} else if (localid >= 255 && apic_mode == LOCAL_APIC) {
			cmn_err(CE_WARN, "!apic: system is in APIC mode, "
			    "can't support x2APIC processor.");
			return (ENOTSUP);
		}
		break;

	default:
		cmn_err(CE_WARN,
		    "!apic: unknown argument type %d to apic_cpu_add().",
		    ap->type);
		return (EINVAL);
	}

	/* Use apic_ioapic_lock to sync with apic_get_next_bind_cpu. */
	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	/* Check whether local APIC id already exists. */
	for (i = 0; i < apic_nproc; i++) {
		if (!CPU_IN_SET(apic_cpumask, i))
			continue;
		if (apic_cpus[i].aci_local_id == localid) {
			lock_clear(&apic_ioapic_lock);
			intr_restore(iflag);
			cmn_err(CE_WARN,
			    "!apic: local apic id %u already exists.",
			    localid);
			return (EEXIST);
		} else if (apic_cpus[i].aci_processor_id == procid) {
			lock_clear(&apic_ioapic_lock);
			intr_restore(iflag);
			cmn_err(CE_WARN,
			    "!apic: processor id %u already exists.",
			    (int)procid);
			return (EEXIST);
		}

		/*
		 * There's no local APIC version number available in MADT table,
		 * so assume that all CPUs are homogeneous and use local APIC
		 * version number of the first existing CPU.
		 */
		if (first) {
			first = B_FALSE;
			localver = apic_cpus[i].aci_local_ver;
		}
	}
	ASSERT(first == B_FALSE);

	/*
	 * Try to assign the same cpuid if APIC id exists in the dirty cache.
	 */
	for (i = 0; i < apic_max_nproc; i++) {
		if (CPU_IN_SET(apic_cpumask, i)) {
			ASSERT((apic_cpus[i].aci_status & APIC_CPU_FREE) == 0);
			continue;
		}
		ASSERT(apic_cpus[i].aci_status & APIC_CPU_FREE);
		if ((apic_cpus[i].aci_status & APIC_CPU_DIRTY) &&
		    apic_cpus[i].aci_local_id == localid &&
		    apic_cpus[i].aci_processor_id == procid) {
			cpuid = i;
			break;
		}
	}

	/* Avoid the dirty cache and allocate fresh slot if possible. */
	if (cpuid == (processorid_t)-1) {
		for (i = 0; i < apic_max_nproc; i++) {
			if ((apic_cpus[i].aci_status & APIC_CPU_FREE) &&
			    (apic_cpus[i].aci_status & APIC_CPU_DIRTY) == 0) {
				cpuid = i;
				break;
			}
		}
	}

	/* Try to find any free slot as last resort. */
	if (cpuid == (processorid_t)-1) {
		for (i = 0; i < apic_max_nproc; i++) {
			if (apic_cpus[i].aci_status & APIC_CPU_FREE) {
				cpuid = i;
				break;
			}
		}
	}

	if (cpuid == (processorid_t)-1) {
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
		cmn_err(CE_NOTE,
		    "!apic: failed to allocate cpu id for processor %u.",
		    procid);
		rv = EAGAIN;
	} else if (ACPI_FAILURE(acpica_map_cpu(cpuid, procid))) {
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
		cmn_err(CE_NOTE,
		    "!apic: failed to build mapping for processor %u.",
		    procid);
		rv = EBUSY;
	} else {
		ASSERT(cpuid >= 0 && cpuid < NCPU);
		ASSERT(cpuid < apic_max_nproc && cpuid < max_ncpus);
		bzero(&apic_cpus[cpuid], sizeof (apic_cpus[0]));
		apic_cpus[cpuid].aci_processor_id = procid;
		apic_cpus[cpuid].aci_local_id = localid;
		apic_cpus[cpuid].aci_local_ver = localver;
		CPUSET_ATOMIC_ADD(apic_cpumask, cpuid);
		if (cpuid >= apic_nproc) {
			apic_nproc = cpuid + 1;
		}
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
		reqp->req.cpu_add.cpuid = cpuid;
	}

	return (rv);
}

int
apic_cpu_remove(psm_cpu_request_t *reqp)
{
	int i;
	ulong_t iflag;
	processorid_t cpuid;

	/* Check whether CPU hotplug is supported. */
	if (!plat_dr_support_cpu() || apic_max_nproc == -1) {
		return (ENOTSUP);
	}

	cpuid = reqp->req.cpu_remove.cpuid;

	/* Use apic_ioapic_lock to sync with apic_get_next_bind_cpu. */
	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	if (!apic_cpu_in_range(cpuid)) {
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
		cmn_err(CE_WARN,
		    "!apic: cpuid %d doesn't exist in apic_cpus array.",
		    cpuid);
		return (ENODEV);
	}
	ASSERT((apic_cpus[cpuid].aci_status & APIC_CPU_FREE) == 0);

	if (ACPI_FAILURE(acpica_unmap_cpu(cpuid))) {
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
		return (ENOENT);
	}

	if (cpuid == apic_nproc - 1) {
		/*
		 * We are removing the highest numbered cpuid so we need to
		 * find the next highest cpuid as the new value for apic_nproc.
		 */
		for (i = apic_nproc; i > 0; i--) {
			if (CPU_IN_SET(apic_cpumask, i - 1)) {
				apic_nproc = i;
				break;
			}
		}
		/* at least one CPU left */
		ASSERT(i > 0);
	}
	CPUSET_ATOMIC_DEL(apic_cpumask, cpuid);
	/* mark slot as free and keep it in the dirty cache */
	apic_cpus[cpuid].aci_status = APIC_CPU_FREE | APIC_CPU_DIRTY;

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	return (0);
}

/*
 * Return the number of ticks the APIC decrements in SF nanoseconds.
 * The fixed-frequency PIT (aka 8254) is used for the measurement.
 */
static uint64_t
apic_calibrate_impl()
{
	uint8_t		pit_tick_lo;
	uint16_t	pit_tick, target_pit_tick, pit_ticks_adj;
	uint32_t	pit_ticks;
	uint32_t	start_apic_tick, end_apic_tick, apic_ticks;
	ulong_t		iflag;

	apic_reg_ops->apic_write(APIC_DIVIDE_REG, apic_divide_reg_init);
	apic_reg_ops->apic_write(APIC_INIT_COUNT, APIC_MAXVAL);

	iflag = intr_clear();

	do {
		pit_tick_lo = inb(PITCTR0_PORT);
		pit_tick = (inb(PITCTR0_PORT) << 8) | pit_tick_lo;
	} while (pit_tick < APIC_TIME_MIN ||
	    pit_tick_lo <= APIC_LB_MIN || pit_tick_lo >= APIC_LB_MAX);

	/*
	 * Wait for the PIT to decrement by 5 ticks to ensure
	 * we didn't start in the middle of a tick.
	 * Compare with 0x10 for the wrap around case.
	 */
	target_pit_tick = pit_tick - 5;
	do {
		pit_tick_lo = inb(PITCTR0_PORT);
		pit_tick = (inb(PITCTR0_PORT) << 8) | pit_tick_lo;
	} while (pit_tick > target_pit_tick || pit_tick_lo < 0x10);

	start_apic_tick = apic_reg_ops->apic_read(APIC_CURR_COUNT);

	/*
	 * Wait for the PIT to decrement by APIC_TIME_COUNT ticks
	 */
	target_pit_tick = pit_tick - APIC_TIME_COUNT;
	do {
		pit_tick_lo = inb(PITCTR0_PORT);
		pit_tick = (inb(PITCTR0_PORT) << 8) | pit_tick_lo;
	} while (pit_tick > target_pit_tick || pit_tick_lo < 0x10);

	end_apic_tick = apic_reg_ops->apic_read(APIC_CURR_COUNT);

	intr_restore(iflag);

	apic_ticks = start_apic_tick - end_apic_tick;

	/* The PIT might have decremented by more ticks than planned */
	pit_ticks_adj = target_pit_tick - pit_tick;
	/* total number of PIT ticks corresponding to apic_ticks */
	pit_ticks = APIC_TIME_COUNT + pit_ticks_adj;

	/*
	 * Determine the number of nanoseconds per APIC clock tick
	 * and then determine how many APIC ticks to interrupt at the
	 * desired frequency
	 * apic_ticks / (pitticks / PIT_HZ) = apic_ticks_per_s
	 * (apic_ticks * PIT_HZ) / pitticks = apic_ticks_per_s
	 * apic_ticks_per_ns = (apic_ticks * PIT_HZ) / (pitticks * 10^9)
	 * apic_ticks_per_SFns =
	 * (SF * apic_ticks * PIT_HZ) / (pitticks * 10^9)
	 */
	return ((SF * apic_ticks * PIT_HZ) / ((uint64_t)pit_ticks * NANOSEC));
}

/*
 * It was found empirically that 5 measurements seem sufficient to give a good
 * accuracy. Most spurious measurements are higher than the target value thus
 * we eliminate up to 2/5 spurious measurements.
 */
#define	APIC_CALIBRATE_MEASUREMENTS		5

#define	APIC_CALIBRATE_PERCENT_OFF_WARNING	10

/*
 * Return the number of ticks the APIC decrements in SF nanoseconds.
 * Several measurements are taken to filter out outliers.
 */
uint64_t
apic_calibrate()
{
	uint64_t	measurements[APIC_CALIBRATE_MEASUREMENTS];
	int		median_idx;
	uint64_t	median;

	/*
	 * When running under a virtual machine, the emulated PIT and APIC
	 * counters do not always return the right values and can roll over.
	 * Those spurious measurements are relatively rare but could
	 * significantly affect the calibration.
	 * Therefore we take several measurements and then keep the median.
	 * The median is preferred to the average here as we only want to
	 * discard outliers.
	 */
	for (int i = 0; i < APIC_CALIBRATE_MEASUREMENTS; i++)
		measurements[i] = apic_calibrate_impl();

	/*
	 * sort results and retrieve median.
	 */
	for (int i = 0; i < APIC_CALIBRATE_MEASUREMENTS; i++) {
		for (int j = i + 1; j < APIC_CALIBRATE_MEASUREMENTS; j++) {
			if (measurements[j] < measurements[i]) {
				uint64_t tmp = measurements[i];
				measurements[i] = measurements[j];
				measurements[j] = tmp;
			}
		}
	}
	median_idx = APIC_CALIBRATE_MEASUREMENTS / 2;
	median = measurements[median_idx];

#if (APIC_CALIBRATE_MEASUREMENTS >= 3)
	/*
	 * Check that measurements are consistent. Post a warning
	 * if the three middle values are not close to each other.
	 */
	uint64_t delta_warn = median *
	    APIC_CALIBRATE_PERCENT_OFF_WARNING / 100;
	if ((median - measurements[median_idx - 1]) > delta_warn ||
	    (measurements[median_idx + 1] - median) > delta_warn) {
		cmn_err(CE_WARN, "apic_calibrate measurements lack "
		    "precision: %llu, %llu, %llu.",
		    (u_longlong_t)measurements[median_idx - 1],
		    (u_longlong_t)median,
		    (u_longlong_t)measurements[median_idx + 1]);
	}
#endif

	return (median);
}

/*
 * Initialise the APIC timer on the local APIC of CPU 0 to the desired
 * frequency.  Note at this stage in the boot sequence, the boot processor
 * is the only active processor.
 * hertz value of 0 indicates a one-shot mode request.  In this case
 * the function returns the resolution (in nanoseconds) for the hardware
 * timer interrupt.  If one-shot mode capability is not available,
 * the return value will be 0. apic_enable_oneshot is a global switch
 * for disabling the functionality.
 * A non-zero positive value for hertz indicates a periodic mode request.
 * In this case the hardware will be programmed to generate clock interrupts
 * at hertz frequency and returns the resolution of interrupts in
 * nanosecond.
 */

int
apic_clkinit(int hertz)
{
	int		ret;

	apic_int_busy_mark = (apic_int_busy_mark *
	    apic_sample_factor_redistribution) / 100;
	apic_int_free_mark = (apic_int_free_mark *
	    apic_sample_factor_redistribution) / 100;
	apic_diff_for_redistribution = (apic_diff_for_redistribution *
	    apic_sample_factor_redistribution) / 100;

	ret = apic_timer_init(hertz);
	return (ret);

}

/*
 * apic_preshutdown:
 * Called early in shutdown whilst we can still access filesystems to do
 * things like loading modules which will be required to complete shutdown
 * after filesystems are all unmounted.
 */
void
apic_preshutdown(int cmd, int fcn)
{
	APIC_VERBOSE_POWEROFF(("apic_preshutdown(%d,%d); m=%d a=%d\n",
	    cmd, fcn, apic_poweroff_method, apic_enable_acpi));
}

void
apic_shutdown(int cmd, int fcn)
{
	int restarts, attempts;
	int i;
	uchar_t	byte;
	ulong_t iflag;

	hpet_acpi_fini();

	/* Send NMI to all CPUs except self to do per processor shutdown */
	iflag = intr_clear();
#ifdef	DEBUG
	APIC_AV_PENDING_SET();
#else
	if (apic_mode == LOCAL_APIC)
		APIC_AV_PENDING_SET();
#endif /* DEBUG */
	apic_shutdown_processors = 1;
	apic_reg_ops->apic_write(APIC_INT_CMD1,
	    AV_NMI | AV_LEVEL | AV_SH_ALL_EXCSELF);

	/* restore cmos shutdown byte before reboot */
	if (apic_cmos_ssb_set) {
		outb(CMOS_ADDR, SSB);
		outb(CMOS_DATA, 0);
	}

	ioapic_disable_redirection();

	/*	disable apic mode if imcr present	*/
	if (apic_imcrp) {
		outb(APIC_IMCR_P1, (uchar_t)APIC_IMCR_SELECT);
		outb(APIC_IMCR_P2, (uchar_t)APIC_IMCR_PIC);
	}

	apic_disable_local_apic();

	intr_restore(iflag);

	/* remainder of function is for shutdown cases only */
	if (cmd != A_SHUTDOWN)
		return;

	/*
	 * Switch system back into Legacy-Mode if using ACPI and
	 * not powering-off.  Some BIOSes need to remain in ACPI-mode
	 * for power-off to succeed (Dell Dimension 4600)
	 * Do not disable ACPI while doing fastreboot
	 */
	if (apic_enable_acpi && fcn != AD_POWEROFF && fcn != AD_FASTREBOOT)
		(void) AcpiDisable();

	if (fcn == AD_FASTREBOOT) {
		apic_reg_ops->apic_write(APIC_INT_CMD1,
		    AV_ASSERT | AV_RESET | AV_SH_ALL_EXCSELF);
	}

	/* remainder of function is for shutdown+poweroff case only */
	if (fcn != AD_POWEROFF)
		return;

	switch (apic_poweroff_method) {
		case APIC_POWEROFF_VIA_RTC:

			/* select the extended NVRAM bank in the RTC */
			outb(CMOS_ADDR, RTC_REGA);
			byte = inb(CMOS_DATA);
			outb(CMOS_DATA, (byte | EXT_BANK));

			outb(CMOS_ADDR, PFR_REG);

			/* for Predator must toggle the PAB bit */
			byte = inb(CMOS_DATA);

			/*
			 * clear power active bar, wakeup alarm and
			 * kickstart
			 */
			byte &= ~(PAB_CBIT | WF_FLAG | KS_FLAG);
			outb(CMOS_DATA, byte);

			/* delay before next write */
			drv_usecwait(1000);

			/* for S40 the following would suffice */
			byte = inb(CMOS_DATA);

			/* power active bar control bit */
			byte |= PAB_CBIT;
			outb(CMOS_DATA, byte);

			break;

		case APIC_POWEROFF_VIA_ASPEN_BMC:
			restarts = 0;
restart_aspen_bmc:
			if (++restarts == 3)
				break;
			attempts = 0;
			do {
				byte = inb(MISMIC_FLAG_REGISTER);
				byte &= MISMIC_BUSY_MASK;
				if (byte != 0) {
					drv_usecwait(1000);
					if (attempts >= 3)
						goto restart_aspen_bmc;
					++attempts;
				}
			} while (byte != 0);
			outb(MISMIC_CNTL_REGISTER, CC_SMS_GET_STATUS);
			byte = inb(MISMIC_FLAG_REGISTER);
			byte |= 0x1;
			outb(MISMIC_FLAG_REGISTER, byte);
			i = 0;
			for (; i < (sizeof (aspen_bmc)/sizeof (aspen_bmc[0]));
			    i++) {
				attempts = 0;
				do {
					byte = inb(MISMIC_FLAG_REGISTER);
					byte &= MISMIC_BUSY_MASK;
					if (byte != 0) {
						drv_usecwait(1000);
						if (attempts >= 3)
							goto restart_aspen_bmc;
						++attempts;
					}
				} while (byte != 0);
				outb(MISMIC_CNTL_REGISTER, aspen_bmc[i].cntl);
				outb(MISMIC_DATA_REGISTER, aspen_bmc[i].data);
				byte = inb(MISMIC_FLAG_REGISTER);
				byte |= 0x1;
				outb(MISMIC_FLAG_REGISTER, byte);
			}
			break;

		case APIC_POWEROFF_VIA_SITKA_BMC:
			restarts = 0;
restart_sitka_bmc:
			if (++restarts == 3)
				break;
			attempts = 0;
			do {
				byte = inb(SMS_STATUS_REGISTER);
				byte &= SMS_STATE_MASK;
				if ((byte == SMS_READ_STATE) ||
				    (byte == SMS_WRITE_STATE)) {
					drv_usecwait(1000);
					if (attempts >= 3)
						goto restart_sitka_bmc;
					++attempts;
				}
			} while ((byte == SMS_READ_STATE) ||
			    (byte == SMS_WRITE_STATE));
			outb(SMS_COMMAND_REGISTER, SMS_GET_STATUS);
			i = 0;
			for (; i < (sizeof (sitka_bmc)/sizeof (sitka_bmc[0]));
			    i++) {
				attempts = 0;
				do {
					byte = inb(SMS_STATUS_REGISTER);
					byte &= SMS_IBF_MASK;
					if (byte != 0) {
						drv_usecwait(1000);
						if (attempts >= 3)
							goto restart_sitka_bmc;
						++attempts;
					}
				} while (byte != 0);
				outb(sitka_bmc[i].port, sitka_bmc[i].data);
			}
			break;

		case APIC_POWEROFF_NONE:

			/* If no APIC direct method, we will try using ACPI */
			if (apic_enable_acpi) {
				if (acpi_poweroff() == 1)
					return;
			} else
				return;

			break;
	}
	/*
	 * Wait a limited time here for power to go off.
	 * If the power does not go off, then there was a
	 * problem and we should continue to the halt which
	 * prints a message for the user to press a key to
	 * reboot.
	 */
	drv_usecwait(7000000); /* wait seven seconds */

}

cyclic_id_t apic_cyclic_id;

/*
 * The following functions are in the platform specific file so that they
 * can be different functions depending on whether we are running on
 * bare metal or a hypervisor.
 */

/*
 * map an apic for memory-mapped access
 */
uint32_t *
mapin_apic(uint32_t addr, size_t len, int flags)
{
	return ((void *)psm_map_phys(addr, len, flags));
}

uint32_t *
mapin_ioapic(uint32_t addr, size_t len, int flags)
{
	return (mapin_apic(addr, len, flags));
}

/*
 * unmap an apic
 */
void
mapout_apic(caddr_t addr, size_t len)
{
	psm_unmap_phys(addr, len);
}

void
mapout_ioapic(caddr_t addr, size_t len)
{
	mapout_apic(addr, len);
}

uint32_t
ioapic_read(int ioapic_ix, uint32_t reg)
{
	volatile uint32_t *ioapic;

	ioapic = apicioadr[ioapic_ix];
	ioapic[APIC_IO_REG] = reg;
	return (ioapic[APIC_IO_DATA]);
}

void
ioapic_write(int ioapic_ix, uint32_t reg, uint32_t value)
{
	volatile uint32_t *ioapic;

	ioapic = apicioadr[ioapic_ix];
	ioapic[APIC_IO_REG] = reg;
	ioapic[APIC_IO_DATA] = value;
}

void
ioapic_write_eoi(int ioapic_ix, uint32_t value)
{
	volatile uint32_t *ioapic;

	ioapic = apicioadr[ioapic_ix];
	ioapic[APIC_IO_EOI] = value;
}

/*
 * Round-robin algorithm to find the next CPU with interrupts enabled.
 * It can't share the same static variable apic_next_bind_cpu with
 * apic_get_next_bind_cpu(), since that will cause all interrupts to be
 * bound to CPU1 at boot time.  During boot, only CPU0 is online with
 * interrupts enabled when apic_get_next_bind_cpu() and apic_find_cpu()
 * are called.  However, the pcplusmp driver assumes that there will be
 * boot_ncpus CPUs configured eventually so it tries to distribute all
 * interrupts among CPU0 - CPU[boot_ncpus - 1].  Thus to prevent all
 * interrupts being targetted at CPU1, we need to use a dedicated static
 * variable for find_next_cpu() instead of sharing apic_next_bind_cpu.
 */

processorid_t
apic_find_cpu(int flag)
{
	int i;
	static processorid_t acid = 0;

	/* Find the first CPU with the passed-in flag set */
	for (i = 0; i < apic_nproc; i++) {
		if (++acid >= apic_nproc) {
			acid = 0;
		}
		if (apic_cpu_in_range(acid) &&
		    (apic_cpus[acid].aci_status & flag)) {
			break;
		}
	}

	ASSERT((apic_cpus[acid].aci_status & flag) != 0);
	return (acid);
}

void
apic_intrmap_init(int apic_mode)
{
	int suppress_brdcst_eoi = 0;

	/*
	 * Intel Software Developer's Manual 3A, 10.12.7:
	 *
	 * Routing of device interrupts to local APIC units operating in
	 * x2APIC mode requires use of the interrupt-remapping architecture
	 * specified in the Intel Virtualization Technology for Directed
	 * I/O, Revision 1.3.  Because of this, BIOS must enumerate support
	 * for and software must enable this interrupt remapping with
	 * Extended Interrupt Mode Enabled before it enabling x2APIC mode in
	 * the local APIC units.
	 *
	 *
	 * In other words, to use the APIC in x2APIC mode, we need interrupt
	 * remapping.  Since we don't start up the IOMMU by default, we
	 * won't be able to do any interrupt remapping and therefore have to
	 * use the APIC in traditional 'local APIC' mode with memory mapped
	 * I/O.
	 */

	if (psm_vt_ops != NULL) {
		if (((apic_intrmap_ops_t *)psm_vt_ops)->
		    apic_intrmap_init(apic_mode) == DDI_SUCCESS) {

			apic_vt_ops = psm_vt_ops;

			/*
			 * We leverage the interrupt remapping engine to
			 * suppress broadcast EOI; thus we must send the
			 * directed EOI with the directed-EOI handler.
			 */
			if (apic_directed_EOI_supported() == 0) {
				suppress_brdcst_eoi = 1;
			}

			apic_vt_ops->apic_intrmap_enable(suppress_brdcst_eoi);

			if (apic_detect_x2apic()) {
				apic_enable_x2apic();
			}

			if (apic_directed_EOI_supported() == 0) {
				apic_set_directed_EOI_handler();
			}
		}
	}
}

/*ARGSUSED*/
static void
apic_record_ioapic_rdt(void *intrmap_private, ioapic_rdt_t *irdt)
{
	irdt->ir_hi <<= APIC_ID_BIT_OFFSET;
}

/*ARGSUSED*/
static void
apic_record_msi(void *intrmap_private, msi_regs_t *mregs)
{
	mregs->mr_addr = MSI_ADDR_HDR |
	    (MSI_ADDR_RH_FIXED << MSI_ADDR_RH_SHIFT) |
	    (MSI_ADDR_DM_PHYSICAL << MSI_ADDR_DM_SHIFT) |
	    (mregs->mr_addr << MSI_ADDR_DEST_SHIFT);
	mregs->mr_data = (MSI_DATA_TM_EDGE << MSI_DATA_TM_SHIFT) |
	    mregs->mr_data;
}

/*
 * Functions from apic_introp.c
 *
 * Those functions are used by apic_intr_ops().
 */

/*
 * MSI support flag:
 * reflects whether MSI is supported at APIC level
 * it can also be patched through /etc/system
 *
 *  0 = default value - don't know and need to call apic_check_msi_support()
 *      to find out then set it accordingly
 *  1 = supported
 * -1 = not supported
 */
int	apic_support_msi = 0;

/* Multiple vector support for MSI-X */
int	apic_msix_enable = 1;

/* Multiple vector support for MSI */
int	apic_multi_msi_enable = 1;

/*
 * Check whether the system supports MSI.
 *
 * MSI is required for PCI-E and for PCI versions later than 2.2, so if we find
 * a PCI-E bus or we find a PCI bus whose version we know is >= 2.2, then we
 * return PSM_SUCCESS to indicate this system supports MSI.
 *
 * (Currently the only way we check whether a given PCI bus supports >= 2.2 is
 * by detecting if we are running inside the KVM hypervisor, which guarantees
 * this version number.)
 */
int
apic_check_msi_support()
{
	dev_info_t *cdip;
	char dev_type[16];
	int dev_len;
	int hwenv = get_hwenv();

	DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support:\n"));

	/*
	 * check whether the first level children of root_node have
	 * PCI-E or PCI capability.
	 */
	for (cdip = ddi_get_child(ddi_root_node()); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {

		DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support: cdip: 0x%p,"
		    " driver: %s, binding: %s, nodename: %s\n", (void *)cdip,
		    ddi_driver_name(cdip), ddi_binding_name(cdip),
		    ddi_node_name(cdip)));
		dev_len = sizeof (dev_type);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "device_type", (caddr_t)dev_type, &dev_len)
		    != DDI_PROP_SUCCESS)
			continue;
		if (strcmp(dev_type, "pciex") == 0)
			return (PSM_SUCCESS);
		if (strcmp(dev_type, "pci") == 0 &&
		    (hwenv == HW_KVM || hwenv == HW_BHYVE))
			return (PSM_SUCCESS);
	}

	/* MSI is not supported on this system */
	DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support: no 'pciex' "
	    "device_type found\n"));
	return (PSM_FAILURE);
}

/*
 * apic_pci_msi_unconfigure:
 *
 * This and next two interfaces are copied from pci_intr_lib.c
 * Do ensure that these two files stay in sync.
 * These needed to be copied over here to avoid a deadlock situation on
 * certain mp systems that use MSI interrupts.
 *
 * IMPORTANT regards next three interfaces:
 * i) are called only for MSI/X interrupts.
 * ii) called with interrupts disabled, and must not block
 */
void
apic_pci_msi_unconfigure(dev_info_t *rdip, int type, int inum)
{
	ushort_t		msi_ctrl;
	int			cap_ptr = i_ddi_get_msi_msix_cap_ptr(rdip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(rdip);

	ASSERT((handle != NULL) && (cap_ptr != 0));

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);
		msi_ctrl &= (~PCI_MSI_MME_MASK);
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);
		pci_config_put32(handle, cap_ptr + PCI_MSI_ADDR_OFFSET, 0);

		if (msi_ctrl &  PCI_MSI_64BIT_MASK) {
			pci_config_put16(handle,
			    cap_ptr + PCI_MSI_64BIT_DATA, 0);
			pci_config_put32(handle,
			    cap_ptr + PCI_MSI_ADDR_OFFSET + 4, 0);
		} else {
			pci_config_put16(handle,
			    cap_ptr + PCI_MSI_32BIT_DATA, 0);
		}

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		uint32_t	mask;
		ddi_intr_msix_t	*msix_p = i_ddi_get_msix(rdip);

		ASSERT(msix_p != NULL);

		/* Offset into "inum"th entry in the MSI-X table & mask it */
		off = (uintptr_t)msix_p->msix_tbl_addr + (inum *
		    PCI_MSIX_VECTOR_SIZE) + PCI_MSIX_VECTOR_CTRL_OFFSET;

		mask = ddi_get32(msix_p->msix_tbl_hdl, (uint32_t *)off);

		ddi_put32(msix_p->msix_tbl_hdl, (uint32_t *)off, (mask | 1));

		/* Offset into the "inum"th entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr +
		    (inum * PCI_MSIX_VECTOR_SIZE);

		/* Reset the "data" and "addr" bits */
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET), 0);
		ddi_put64(msix_p->msix_tbl_hdl, (uint64_t *)off, 0);
	}
}

/*
 * apic_pci_msi_disable_mode:
 */
void
apic_pci_msi_disable_mode(dev_info_t *rdip, int type)
{
	ushort_t		msi_ctrl;
	int			cap_ptr = i_ddi_get_msi_msix_cap_ptr(rdip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(rdip);

	ASSERT((handle != NULL) && (cap_ptr != 0));

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);
		if (!(msi_ctrl & PCI_MSI_ENABLE_BIT))
			return;

		msi_ctrl &= ~PCI_MSI_ENABLE_BIT;	/* MSI disable */
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSIX_CTRL);
		if (msi_ctrl & PCI_MSIX_ENABLE_BIT) {
			msi_ctrl &= ~PCI_MSIX_ENABLE_BIT;
			pci_config_put16(handle, cap_ptr + PCI_MSIX_CTRL,
			    msi_ctrl);
		}
	}
}

uint32_t
apic_get_localapicid(uint32_t cpuid)
{
	ASSERT(cpuid < apic_nproc && apic_cpus != NULL);

	return (apic_cpus[cpuid].aci_local_id);
}

uchar_t
apic_get_ioapicid(uchar_t ioapicindex)
{
	ASSERT(ioapicindex < MAX_IO_APIC);

	return (apic_io_id[ioapicindex]);
}
