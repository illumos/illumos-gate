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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/hpet_acpi.h>
#include <sys/hpet.h>
#include <sys/bitmap.h>
#include <sys/inttypes.h>
#include <sys/time.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/apic.h>
#include <sys/callb.h>
#include <sys/clock.h>
#include <sys/archsystm.h>
#include <sys/cpupart.h>

static int hpet_init_proxy(int *hpet_vect, iflag_t *hpet_flags);
static boolean_t hpet_install_proxy(void);
static boolean_t hpet_callback(int code);
static boolean_t hpet_cpr(int code);
static boolean_t hpet_resume(void);
static void hpet_cst_callback(uint32_t code);
static boolean_t hpet_deep_idle_config(int code);
static int hpet_validate_table(ACPI_TABLE_HPET *hpet_table);
static boolean_t hpet_checksum_table(unsigned char *table, unsigned int len);
static void *hpet_memory_map(ACPI_TABLE_HPET *hpet_table);
static int hpet_start_main_counter(hpet_info_t *hip);
static int hpet_stop_main_counter(hpet_info_t *hip);
static uint64_t hpet_read_main_counter_value(hpet_info_t *hip);
static uint64_t hpet_set_leg_rt_cnf(hpet_info_t *hip, uint32_t new_value);
static uint64_t hpet_read_gen_cap(hpet_info_t *hip);
static uint64_t hpet_read_gen_config(hpet_info_t *hip);
static uint64_t hpet_read_gen_intrpt_stat(hpet_info_t *hip);
static uint64_t hpet_read_timer_N_config(hpet_info_t *hip, uint_t n);
static hpet_TN_conf_cap_t hpet_convert_timer_N_config(uint64_t conf);
static void hpet_write_gen_config(hpet_info_t *hip, uint64_t l);
static void hpet_write_gen_intrpt_stat(hpet_info_t *hip, uint64_t l);
static void hpet_write_timer_N_config(hpet_info_t *hip, uint_t n, uint64_t l);
static void hpet_write_timer_N_comp(hpet_info_t *hip, uint_t n, uint64_t l);
static void hpet_disable_timer(hpet_info_t *hip, uint32_t timer_n);
static void hpet_enable_timer(hpet_info_t *hip, uint32_t timer_n);
static int hpet_get_IOAPIC_intr_capable_timer(hpet_info_t *hip);
static int hpet_timer_available(uint32_t allocated_timers, uint32_t n);
static void hpet_timer_alloc(uint32_t *allocated_timers, uint32_t n);
static void hpet_timer_set_up(hpet_info_t *hip, uint32_t timer_n,
    uint32_t interrupt);
static uint_t hpet_isr(char *arg);
static uint32_t hpet_install_interrupt_handler(uint_t (*func)(char *),
    int vector);
static void hpet_uninstall_interrupt_handler(void);
static void hpet_expire_all(void);
static boolean_t hpet_guaranteed_schedule(hrtime_t required_wakeup_time);
static boolean_t hpet_use_hpet_timer(hrtime_t *expire);
static void hpet_use_lapic_timer(hrtime_t expire);
static void hpet_init_proxy_data(void);

/*
 * hpet_state_lock is used to synchronize disabling/enabling deep c-states
 * and to synchronize suspend/resume.
 */
static kmutex_t		hpet_state_lock;
static struct hpet_state {
	boolean_t	proxy_installed;	/* CBE proxy interrupt setup */
	boolean_t	cpr;			/* currently in CPR */
	boolean_t	cpu_deep_idle;		/* user enable/disable */
	boolean_t	uni_cstate;		/* disable if only one cstate */
} hpet_state = { B_FALSE, B_FALSE, B_TRUE, B_TRUE};

uint64_t hpet_spin_check = HPET_SPIN_CHECK;
uint64_t hpet_spin_timeout = HPET_SPIN_TIMEOUT;
uint64_t hpet_idle_spin_timeout = HPET_SPIN_TIMEOUT;
uint64_t hpet_isr_spin_timeout = HPET_SPIN_TIMEOUT;

static kmutex_t		hpet_proxy_lock;	/* lock for lAPIC proxy data */
/*
 * hpet_proxy_users is a per-cpu array.
 */
static hpet_proxy_t	*hpet_proxy_users;	/* one per CPU */


ACPI_TABLE_HPET		*hpet_table;		/* ACPI HPET table */
hpet_info_t		hpet_info;		/* Human readable Information */

/*
 * Provide HPET access from unix.so.
 * Set up pointers to access symbols in pcplusmp.
 */
static void
hpet_establish_hooks(void)
{
	hpet.install_proxy = &hpet_install_proxy;
	hpet.callback = &hpet_callback;
	hpet.use_hpet_timer = &hpet_use_hpet_timer;
	hpet.use_lapic_timer = &hpet_use_lapic_timer;
}

/*
 * Get the ACPI "HPET" table.
 * acpi_probe() calls this function from mp_startup before drivers are loaded.
 * acpi_probe() verified the system is using ACPI before calling this.
 *
 * There may be more than one ACPI HPET table (Itanium only?).
 * Intel's HPET spec defines each timer block to have up to 32 counters and
 * be 1024 bytes long.  There can be more than one timer block of 32 counters.
 * Each timer block would have an additional ACPI HPET table.
 * Typical x86 systems today only have 1 HPET with 3 counters.
 * On x86 we only consume HPET table "1" for now.
 */
int
hpet_acpi_init(int *hpet_vect, iflag_t *hpet_flags)
{
	extern hrtime_t tsc_read(void);
	extern int	idle_cpu_no_deep_c;
	extern int	cpuid_deep_cstates_supported(void);
	void		*la;
	uint64_t	ret;
	uint_t		num_timers;
	uint_t		ti;

	(void) memset(&hpet_info, 0, sizeof (hpet_info));
	hpet.supported = HPET_NO_SUPPORT;

	if (idle_cpu_no_deep_c)
		return (DDI_FAILURE);

	if (!cpuid_deep_cstates_supported())
		return (DDI_FAILURE);

	hpet_establish_hooks();

	/*
	 * Get HPET ACPI table 1.
	 */
	if (ACPI_FAILURE(AcpiGetTable(ACPI_SIG_HPET, HPET_TABLE_1,
	    (ACPI_TABLE_HEADER **)&hpet_table))) {
		cmn_err(CE_NOTE, "!hpet_acpi: unable to get ACPI HPET table");
		return (DDI_FAILURE);
	}

	if (hpet_validate_table(hpet_table) != AE_OK) {
		cmn_err(CE_NOTE, "!hpet_acpi: invalid HPET table");
		return (DDI_FAILURE);
	}

	la = hpet_memory_map(hpet_table);
	if (la == NULL) {
		cmn_err(CE_NOTE, "!hpet_acpi: memory map HPET failed");
		return (DDI_FAILURE);
	}
	hpet_info.logical_address = la;

	ret = hpet_read_gen_cap(&hpet_info);
	hpet_info.gen_cap.counter_clk_period = HPET_GCAP_CNTR_CLK_PERIOD(ret);
	hpet_info.gen_cap.vendor_id = HPET_GCAP_VENDOR_ID(ret);
	hpet_info.gen_cap.leg_route_cap = HPET_GCAP_LEG_ROUTE_CAP(ret);
	hpet_info.gen_cap.count_size_cap = HPET_GCAP_CNT_SIZE_CAP(ret);
	/*
	 * Hardware contains the last timer's number.
	 * Add 1 to get the number of timers.
	 */
	hpet_info.gen_cap.num_tim_cap = HPET_GCAP_NUM_TIM_CAP(ret) + 1;
	hpet_info.gen_cap.rev_id = HPET_GCAP_REV_ID(ret);

	if (hpet_info.gen_cap.counter_clk_period > HPET_MAX_CLK_PERIOD) {
		cmn_err(CE_NOTE, "!hpet_acpi: COUNTER_CLK_PERIOD 0x%lx > 0x%lx",
		    (long)hpet_info.gen_cap.counter_clk_period,
		    (long)HPET_MAX_CLK_PERIOD);
		return (DDI_FAILURE);
	}

	num_timers = (uint_t)hpet_info.gen_cap.num_tim_cap;
	if ((num_timers < 3) || (num_timers > 32)) {
		cmn_err(CE_NOTE, "!hpet_acpi: invalid number of HPET timers "
		    "%lx", (long)num_timers);
		return (DDI_FAILURE);
	}
	hpet_info.timer_n_config = (hpet_TN_conf_cap_t *)kmem_zalloc(
	    num_timers * sizeof (uint64_t), KM_SLEEP);

	ret = hpet_read_gen_config(&hpet_info);
	hpet_info.gen_config.leg_rt_cnf = HPET_GCFR_LEG_RT_CNF_BITX(ret);
	hpet_info.gen_config.enable_cnf = HPET_GCFR_ENABLE_CNF_BITX(ret);

	/*
	 * Solaris does not use the HPET Legacy Replacement Route capabilities.
	 * This feature has been off by default on test systems.
	 * The HPET spec does not specify if Legacy Replacement Route is
	 * on or off by default, so we explicitely set it off here.
	 * It should not matter which mode the HPET is in since we use
	 * the first available non-legacy replacement timer: timer 2.
	 */
	(void) hpet_set_leg_rt_cnf(&hpet_info, 0);

	ret = hpet_read_gen_config(&hpet_info);
	hpet_info.gen_config.leg_rt_cnf = HPET_GCFR_LEG_RT_CNF_BITX(ret);
	hpet_info.gen_config.enable_cnf = HPET_GCFR_ENABLE_CNF_BITX(ret);

	hpet_info.gen_intrpt_stat = hpet_read_gen_intrpt_stat(&hpet_info);
	hpet_info.main_counter_value = hpet_read_main_counter_value(&hpet_info);

	for (ti = 0; ti < num_timers; ++ti) {
		ret = hpet_read_timer_N_config(&hpet_info, ti);
		/*
		 * Make sure no timers are enabled (think fast reboot or
		 * virtual hardware).
		 */
		if (ret & HPET_TIMER_N_INT_ENB_CNF_BIT) {
			hpet_disable_timer(&hpet_info, ti);
			ret &= ~HPET_TIMER_N_INT_ENB_CNF_BIT;
		}

		hpet_info.timer_n_config[ti] = hpet_convert_timer_N_config(ret);
	}

	/*
	 * Be aware the Main Counter may need to be initialized in the future
	 * if it is used for more than just Deep C-State support.
	 * The HPET's Main Counter does not need to be initialize to a specific
	 * value before starting it for use to wake up CPUs from Deep C-States.
	 */
	if (hpet_start_main_counter(&hpet_info) != AE_OK) {
		cmn_err(CE_NOTE, "!hpet_acpi: hpet_start_main_counter failed");
		return (DDI_FAILURE);
	}

	hpet_info.period = hpet_info.gen_cap.counter_clk_period;
	/*
	 * Read main counter twice to record HPET latency for debugging.
	 */
	hpet_info.tsc[0] = tsc_read();
	hpet_info.hpet_main_counter_reads[0] =
	    hpet_read_main_counter_value(&hpet_info);
	hpet_info.tsc[1] = tsc_read();
	hpet_info.hpet_main_counter_reads[1] =
	    hpet_read_main_counter_value(&hpet_info);
	hpet_info.tsc[2] = tsc_read();

	ret = hpet_read_gen_config(&hpet_info);
	hpet_info.gen_config.leg_rt_cnf = HPET_GCFR_LEG_RT_CNF_BITX(ret);
	hpet_info.gen_config.enable_cnf = HPET_GCFR_ENABLE_CNF_BITX(ret);

	/*
	 * HPET main counter reads are supported now.
	 */
	hpet.supported = HPET_TIMER_SUPPORT;

	return (hpet_init_proxy(hpet_vect, hpet_flags));
}

void
hpet_acpi_fini(void)
{
	if (hpet.supported == HPET_NO_SUPPORT)
		return;
	if (hpet.supported >= HPET_TIMER_SUPPORT)
		(void) hpet_stop_main_counter(&hpet_info);
	if (hpet.supported > HPET_TIMER_SUPPORT)
		hpet_disable_timer(&hpet_info, hpet_info.cstate_timer.timer);
}

/*
 * Do initial setup to use a HPET timer as a proxy for Deep C-state stalled
 * LAPIC Timers.  Get a free HPET timer that supports I/O APIC routed interrupt.
 * Setup data to handle the timer's ISR, and add the timer's interrupt.
 *
 * The ddi cannot be use to allocate the HPET timer's interrupt.
 * ioapic_init_intr() in mp_platform_common() later sets up the I/O APIC
 * to handle the HPET timer's interrupt.
 *
 * Note: FSB (MSI) interrupts are not currently supported by Intel HPETs as of
 * ICH9.  The HPET spec allows for MSI.  In the future MSI may be prefered.
 */
static int
hpet_init_proxy(int *hpet_vect, iflag_t *hpet_flags)
{
	if (hpet_get_IOAPIC_intr_capable_timer(&hpet_info) == -1) {
		cmn_err(CE_WARN, "!hpet_acpi: get ioapic intr failed.");
		return (DDI_FAILURE);
	}

	hpet_init_proxy_data();

	if (hpet_install_interrupt_handler(&hpet_isr,
	    hpet_info.cstate_timer.intr) != AE_OK) {
		cmn_err(CE_WARN, "!hpet_acpi: install interrupt failed.");
		return (DDI_FAILURE);
	}
	*hpet_vect = hpet_info.cstate_timer.intr;
	hpet_flags->intr_el = INTR_EL_LEVEL;
	hpet_flags->intr_po = INTR_PO_ACTIVE_HIGH;
	hpet_flags->bustype = BUS_PCI;		/*  we *do* conform to PCI */

	/*
	 * Avoid a possibly stuck interrupt by programing the HPET's timer here
	 * before the I/O APIC is programmed to handle this interrupt.
	 */
	hpet_timer_set_up(&hpet_info, hpet_info.cstate_timer.timer,
	    hpet_info.cstate_timer.intr);

	/*
	 * All HPET functionality is supported.
	 */
	hpet.supported = HPET_FULL_SUPPORT;
	return (DDI_SUCCESS);
}

/*
 * Called by kernel if it can support Deep C-States.
 */
static boolean_t
hpet_install_proxy(void)
{
	if (hpet_state.proxy_installed == B_TRUE)
		return (B_TRUE);

	if (hpet.supported != HPET_FULL_SUPPORT)
		return (B_FALSE);

	hpet_enable_timer(&hpet_info, hpet_info.cstate_timer.timer);
	hpet_state.proxy_installed = B_TRUE;

	return (B_TRUE);
}

/*
 * Remove the interrupt that was added with add_avintr() in
 * hpet_install_interrupt_handler().
 */
static void
hpet_uninstall_interrupt_handler(void)
{
	rem_avintr(NULL, CBE_HIGH_PIL, (avfunc)&hpet_isr,
	    hpet_info.cstate_timer.intr);
}

static int
hpet_validate_table(ACPI_TABLE_HPET *hpet_table)
{
	ACPI_TABLE_HEADER	*table_header = (ACPI_TABLE_HEADER *)hpet_table;

	if (table_header->Length != sizeof (ACPI_TABLE_HPET)) {
		cmn_err(CE_WARN, "!hpet_validate_table: Length %lx != sizeof ("
		    "ACPI_TABLE_HPET) %lx.",
		    (unsigned long)((ACPI_TABLE_HEADER *)hpet_table)->Length,
		    (unsigned long)sizeof (ACPI_TABLE_HPET));
		return (AE_ERROR);
	}

	if (!ACPI_COMPARE_NAME(table_header->Signature, ACPI_SIG_HPET)) {
		cmn_err(CE_WARN, "!hpet_validate_table: Invalid HPET table "
		    "signature");
		return (AE_ERROR);
	}

	if (!hpet_checksum_table((unsigned char *)hpet_table,
	    (unsigned int)table_header->Length)) {
		cmn_err(CE_WARN, "!hpet_validate_table: Invalid HPET checksum");
		return (AE_ERROR);
	}

	/*
	 * Sequence should be table number - 1.  We are using table 1.
	 */
	if (hpet_table->Sequence != HPET_TABLE_1 - 1) {
		cmn_err(CE_WARN, "!hpet_validate_table: Invalid Sequence %lx",
		    (long)hpet_table->Sequence);
		return (AE_ERROR);
	}

	return (AE_OK);
}

static boolean_t
hpet_checksum_table(unsigned char *table, unsigned int length)
{
	unsigned char	checksum = 0;
	int		i;

	for (i = 0; i < length; ++i, ++table)
		checksum += *table;

	return (checksum == 0);
}

static void *
hpet_memory_map(ACPI_TABLE_HPET *hpet_table)
{
	return (AcpiOsMapMemory(hpet_table->Address.Address, HPET_SIZE));
}

static int
hpet_start_main_counter(hpet_info_t *hip)
{
	uint64_t	*gcr_ptr;
	uint64_t	gcr;

	gcr_ptr = (uint64_t *)HPET_GEN_CONFIG_ADDRESS(hip->logical_address);
	gcr = *gcr_ptr;

	gcr |= HPET_GCFR_ENABLE_CNF;
	*gcr_ptr = gcr;
	gcr = *gcr_ptr;

	return (gcr & HPET_GCFR_ENABLE_CNF ? AE_OK : ~AE_OK);
}

static int
hpet_stop_main_counter(hpet_info_t *hip)
{
	uint64_t	*gcr_ptr;
	uint64_t	gcr;

	gcr_ptr = (uint64_t *)HPET_GEN_CONFIG_ADDRESS(hip->logical_address);
	gcr = *gcr_ptr;

	gcr &= ~HPET_GCFR_ENABLE_CNF;
	*gcr_ptr = gcr;
	gcr = *gcr_ptr;

	return (gcr & HPET_GCFR_ENABLE_CNF ? ~AE_OK : AE_OK);
}

/*
 * Set the Legacy Replacement Route bit.
 * This should be called before setting up timers.
 * The HPET specification is silent regarding setting this after timers are
 * programmed.
 */
static uint64_t
hpet_set_leg_rt_cnf(hpet_info_t *hip, uint32_t new_value)
{
	uint64_t gen_conf = hpet_read_gen_config(hip);

	switch (new_value) {
	case 0:
		gen_conf &= ~HPET_GCFR_LEG_RT_CNF;
		break;

	case HPET_GCFR_LEG_RT_CNF:
		gen_conf |= HPET_GCFR_LEG_RT_CNF;
		break;

	default:
		ASSERT(new_value == 0 || new_value == HPET_GCFR_LEG_RT_CNF);
		break;
	}
	hpet_write_gen_config(hip, gen_conf);
	return (gen_conf);
}

static uint64_t
hpet_read_gen_cap(hpet_info_t *hip)
{
	return (*(uint64_t *)HPET_GEN_CAP_ADDRESS(hip->logical_address));
}

static uint64_t
hpet_read_gen_config(hpet_info_t *hip)
{
	return (*(uint64_t *)
	    HPET_GEN_CONFIG_ADDRESS(hip->logical_address));
}

static uint64_t
hpet_read_gen_intrpt_stat(hpet_info_t *hip)
{
	hip->gen_intrpt_stat = *(uint64_t *)HPET_GEN_INTR_STAT_ADDRESS(
	    hip->logical_address);
	return (hip->gen_intrpt_stat);
}

static uint64_t
hpet_read_timer_N_config(hpet_info_t *hip, uint_t n)
{
	uint64_t conf = *(uint64_t *)HPET_TIMER_N_CONF_ADDRESS(
	    hip->logical_address, n);
	hip->timer_n_config[n] = hpet_convert_timer_N_config(conf);
	return (conf);
}

static hpet_TN_conf_cap_t
hpet_convert_timer_N_config(uint64_t conf)
{
	hpet_TN_conf_cap_t cc = { 0 };

	cc.int_route_cap = HPET_TIMER_N_INT_ROUTE_CAP(conf);
	cc.fsb_int_del_cap = HPET_TIMER_N_FSB_INT_DEL_CAP(conf);
	cc.fsb_int_en_cnf = HPET_TIMER_N_FSB_EN_CNF(conf);
	cc.int_route_cnf = HPET_TIMER_N_INT_ROUTE_CNF(conf);
	cc.mode32_cnf = HPET_TIMER_N_MODE32_CNF(conf);
	cc.val_set_cnf = HPET_TIMER_N_VAL_SET_CNF(conf);
	cc.size_cap = HPET_TIMER_N_SIZE_CAP(conf);
	cc.per_int_cap = HPET_TIMER_N_PER_INT_CAP(conf);
	cc.type_cnf = HPET_TIMER_N_TYPE_CNF(conf);
	cc.int_enb_cnf = HPET_TIMER_N_INT_ENB_CNF(conf);
	cc.int_type_cnf = HPET_TIMER_N_INT_TYPE_CNF(conf);

	return (cc);
}

static uint64_t
hpet_read_main_counter_value(hpet_info_t *hip)
{
	uint64_t	value;
	uint32_t	*counter;
	uint32_t	high1, high2, low;

	counter = (uint32_t *)HPET_MAIN_COUNTER_ADDRESS(hip->logical_address);

	/*
	 * 32-bit main counters
	 */
	if (hip->gen_cap.count_size_cap == 0) {
		value = (uint64_t)*counter;
		hip->main_counter_value = value;
		return (value);
	}

	/*
	 * HPET spec claims a 64-bit read can be split into two 32-bit reads
	 * by the hardware connection to the HPET.
	 */
	high2 = counter[1];
	do {
		high1 = high2;
		low = counter[0];
		high2 = counter[1];
	} while (high2 != high1);

	value = ((uint64_t)high1 << 32) | low;
	hip->main_counter_value = value;
	return (value);
}

static void
hpet_write_gen_config(hpet_info_t *hip, uint64_t l)
{
	*(uint64_t *)HPET_GEN_CONFIG_ADDRESS(hip->logical_address) = l;
}

static void
hpet_write_gen_intrpt_stat(hpet_info_t *hip, uint64_t l)
{
	*(uint64_t *)HPET_GEN_INTR_STAT_ADDRESS(hip->logical_address) = l;
}

static void
hpet_write_timer_N_config(hpet_info_t *hip, uint_t n, uint64_t l)
{
	if (hip->timer_n_config[n].size_cap == 1)
		*(uint64_t *)HPET_TIMER_N_CONF_ADDRESS(
		    hip->logical_address, n) = l;
	else
		*(uint32_t *)HPET_TIMER_N_CONF_ADDRESS(
		    hip->logical_address, n) = (uint32_t)(0xFFFFFFFF & l);
}

static void
hpet_write_timer_N_comp(hpet_info_t *hip, uint_t n, uint64_t l)
{
	*(uint64_t *)HPET_TIMER_N_COMP_ADDRESS(hip->logical_address, n) = l;
}

static void
hpet_disable_timer(hpet_info_t *hip, uint32_t timer_n)
{
	uint64_t l;

	l = hpet_read_timer_N_config(hip, timer_n);
	l &= ~HPET_TIMER_N_INT_ENB_CNF_BIT;
	hpet_write_timer_N_config(hip, timer_n, l);
}

static void
hpet_enable_timer(hpet_info_t *hip, uint32_t timer_n)
{
	uint64_t l;

	l = hpet_read_timer_N_config(hip, timer_n);
	l |= HPET_TIMER_N_INT_ENB_CNF_BIT;
	hpet_write_timer_N_config(hip, timer_n, l);
}

/*
 * Add the interrupt handler for I/O APIC interrupt number (interrupt line).
 *
 * The I/O APIC line (vector) is programmed in ioapic_init_intr() called
 * from apic_picinit() psm_ops apic_ops entry point after we return from
 * apic_init() psm_ops entry point.
 */
static uint32_t
hpet_install_interrupt_handler(uint_t (*func)(char *), int vector)
{
	uint32_t retval;

	retval = add_avintr(NULL, CBE_HIGH_PIL, (avfunc)func, "HPET Timer",
	    vector, NULL, NULL, NULL, NULL);
	if (retval == 0) {
		cmn_err(CE_WARN, "!hpet_acpi: add_avintr() failed");
		return (AE_BAD_PARAMETER);
	}
	return (AE_OK);
}

/*
 * The HPET timers specify which I/O APIC interrupts they can be routed to.
 * Find the first available non-legacy-replacement timer and its I/O APIC irq.
 * Supported I/O APIC IRQs are specified in the int_route_cap bitmap in each
 * timer's timer_n_config register.
 */
static int
hpet_get_IOAPIC_intr_capable_timer(hpet_info_t *hip)
{
	int	timer;
	int	intr;

	for (timer = HPET_FIRST_NON_LEGACY_TIMER;
	    timer < hip->gen_cap.num_tim_cap; ++timer) {

		if (!hpet_timer_available(hip->allocated_timers, timer))
			continue;

		intr = lowbit(hip->timer_n_config[timer].int_route_cap) - 1;
		if (intr >= 0) {
			hpet_timer_alloc(&hip->allocated_timers, timer);
			hip->cstate_timer.timer = timer;
			hip->cstate_timer.intr = intr;
			return (timer);
		}
	}

	return (-1);
}

/*
 * Mark this timer as used.
 */
static void
hpet_timer_alloc(uint32_t *allocated_timers, uint32_t n)
{
	*allocated_timers |= 1 << n;
}

/*
 * Check if this timer is available.
 * No mutual exclusion because only one thread uses this.
 */
static int
hpet_timer_available(uint32_t allocated_timers, uint32_t n)
{
	return ((allocated_timers & (1 << n)) == 0);
}

/*
 * Setup timer N to route its interrupt to I/O APIC.
 */
static void
hpet_timer_set_up(hpet_info_t *hip, uint32_t timer_n, uint32_t interrupt)
{
	uint64_t conf;

	conf = hpet_read_timer_N_config(hip, timer_n);

	/*
	 * Caller is required to verify this interrupt route is supported.
	 */
	ASSERT(HPET_TIMER_N_INT_ROUTE_CAP(conf) & (1 << interrupt));

	conf &= ~HPET_TIMER_N_FSB_EN_CNF_BIT;	/* use IOAPIC */
	conf |= HPET_TIMER_N_INT_ROUTE_SHIFT(interrupt);
	conf &= ~HPET_TIMER_N_TYPE_CNF_BIT;	/* non periodic */
	conf &= ~HPET_TIMER_N_INT_ENB_CNF_BIT;	/* disabled */
	conf |= HPET_TIMER_N_INT_TYPE_CNF_BIT;	/* Level Triggered */

	hpet_write_timer_N_config(hip, timer_n, conf);
}

/*
 * The HPET's Main Counter is not stopped before programming an HPET timer.
 * This will allow the HPET to be used as a time source.
 * The programmed timer interrupt may occur before this function returns.
 * Callers must block interrupts before calling this function if they must
 * guarantee the interrupt is handled after this function returns.
 *
 * Return 0 if main counter is less than timer after enabling timer.
 * The interrupt was programmed, but it may fire before this returns.
 * Return !0 if main counter is greater than timer after enabling timer.
 * In other words: the timer will not fire, and we do not know if it did fire.
 *
 * delta is in HPET ticks.
 *
 * Writing a 64-bit value to a 32-bit register will "wrap around".
 * A 32-bit HPET timer will wrap around in a little over 5 minutes.
 */
int
hpet_timer_program(hpet_info_t *hip, uint32_t timer, uint64_t delta)
{
	uint64_t time, program;

	program = hpet_read_main_counter_value(hip);
	program += delta;
	hpet_write_timer_N_comp(hip, timer, program);

	time = hpet_read_main_counter_value(hip);
	if (time < program)
		return (AE_OK);

	return (AE_TIME);
}

/*
 * CPR and power policy-change callback entry point.
 */
boolean_t
hpet_callback(int code)
{
	switch (code) {
	case PM_DEFAULT_CPU_DEEP_IDLE:
		/*FALLTHROUGH*/
	case PM_ENABLE_CPU_DEEP_IDLE:
		/*FALLTHROUGH*/
	case PM_DISABLE_CPU_DEEP_IDLE:
		return (hpet_deep_idle_config(code));

	case CB_CODE_CPR_RESUME:
		/*FALLTHROUGH*/
	case CB_CODE_CPR_CHKPT:
		return (hpet_cpr(code));

	case CST_EVENT_MULTIPLE_CSTATES:
		hpet_cst_callback(CST_EVENT_MULTIPLE_CSTATES);
		return (B_TRUE);

	case CST_EVENT_ONE_CSTATE:
		hpet_cst_callback(CST_EVENT_ONE_CSTATE);
		return (B_TRUE);

	default:
		cmn_err(CE_NOTE, "!hpet_callback: invalid code %d\n", code);
		return (B_FALSE);
	}
}

/*
 * According to the HPET spec 1.0a: the Operating System must save and restore
 * HPET event timer hardware context through ACPI sleep state transitions.
 * Timer registers (including the main counter) may not be preserved through
 * ACPI S3, S4, or S5 sleep states.  This code does not not support S1 nor S2.
 *
 * Current HPET state is already in hpet.supported and
 * hpet_state.proxy_installed.  hpet_info contains the proxy interrupt HPET
 * Timer state.
 *
 * Future projects beware: the HPET Main Counter is undefined after ACPI S3 or
 * S4, and it is not saved/restored here.  Future projects cannot expect the
 * Main Counter to be monotomically (or accurately) increasing across CPR.
 *
 * Note: the CPR Checkpoint path later calls pause_cpus() which ensures all
 * CPUs are awake and in a spin loop before the system suspends.  The HPET is
 * not needed for Deep C-state wakeup when CPUs are in cpu_pause().
 * It is safe to leave the HPET running as the system suspends; we just
 * disable the timer from generating interrupts here.
 */
static boolean_t
hpet_cpr(int code)
{
	ulong_t		intr, dead_count = 0;
	hrtime_t	dead = gethrtime() + hpet_spin_timeout;
	boolean_t	ret = B_TRUE;

	mutex_enter(&hpet_state_lock);
	switch (code) {
	case CB_CODE_CPR_CHKPT:
		if (hpet_state.proxy_installed == B_FALSE)
			break;

		hpet_state.cpr = B_TRUE;

		intr = intr_clear();
		while (!mutex_tryenter(&hpet_proxy_lock)) {
			/*
			 * spin
			 */
			intr_restore(intr);
			if (dead_count++ > hpet_spin_check) {
				dead_count = 0;
				if (gethrtime() > dead) {
					hpet_state.cpr = B_FALSE;
					mutex_exit(&hpet_state_lock);
					cmn_err(CE_NOTE, "!hpet_cpr: deadman");
					return (B_FALSE);
				}
			}
			intr = intr_clear();
		}
		hpet_expire_all();
		mutex_exit(&hpet_proxy_lock);
		intr_restore(intr);

		hpet_disable_timer(&hpet_info, hpet_info.cstate_timer.timer);
		break;

	case CB_CODE_CPR_RESUME:
		if (hpet_resume() == B_TRUE)
			hpet_state.cpr = B_FALSE;
		else
			cmn_err(CE_NOTE, "!hpet_resume failed.");
		break;

	default:
		cmn_err(CE_NOTE, "!hpet_cpr: invalid code %d\n", code);
		ret = B_FALSE;
		break;
	}
	mutex_exit(&hpet_state_lock);
	return (ret);
}

/*
 * Assume the HPET stopped in Suspend state and timer state was lost.
 */
static boolean_t
hpet_resume(void)
{
	if (hpet.supported != HPET_TIMER_SUPPORT)
		return (B_TRUE);

	/*
	 * The HPET spec does not specify if Legacy Replacement Route is
	 * on or off by default, so we set it off here.
	 */
	(void) hpet_set_leg_rt_cnf(&hpet_info, 0);

	if (hpet_start_main_counter(&hpet_info) != AE_OK) {
		cmn_err(CE_NOTE, "!hpet_resume: start main counter failed");
		hpet.supported = HPET_NO_SUPPORT;
		if (hpet_state.proxy_installed == B_TRUE) {
			hpet_state.proxy_installed = B_FALSE;
			hpet_uninstall_interrupt_handler();
		}
		return (B_FALSE);
	}

	if (hpet_state.proxy_installed == B_FALSE)
		return (B_TRUE);

	hpet_timer_set_up(&hpet_info, hpet_info.cstate_timer.timer,
	    hpet_info.cstate_timer.intr);
	if (hpet_state.cpu_deep_idle == B_TRUE)
		hpet_enable_timer(&hpet_info, hpet_info.cstate_timer.timer);

	return (B_TRUE);
}

/*
 * Callback to enable/disable Deep C-States based on power.conf setting.
 */
static boolean_t
hpet_deep_idle_config(int code)
{
	ulong_t		intr, dead_count = 0;
	hrtime_t	dead = gethrtime() + hpet_spin_timeout;
	boolean_t	ret = B_TRUE;

	mutex_enter(&hpet_state_lock);
	switch (code) {
	case PM_DEFAULT_CPU_DEEP_IDLE:
		/*FALLTHROUGH*/
	case PM_ENABLE_CPU_DEEP_IDLE:

		if (hpet_state.cpu_deep_idle == B_TRUE)
			break;

		if (hpet_state.proxy_installed == B_FALSE) {
			ret = B_FALSE;  /* Deep C-States not supported */
			break;
		}

		hpet_enable_timer(&hpet_info, hpet_info.cstate_timer.timer);
		hpet_state.cpu_deep_idle = B_TRUE;
		break;

	case PM_DISABLE_CPU_DEEP_IDLE:

		if ((hpet_state.cpu_deep_idle == B_FALSE) ||
		    (hpet_state.proxy_installed == B_FALSE))
			break;

		/*
		 * The order of these operations is important to avoid
		 * lost wakeups: Set a flag to refuse all future LAPIC Timer
		 * proxy requests, then wake up all CPUs from deep C-state,
		 * and finally disable the HPET interrupt-generating timer.
		 */
		hpet_state.cpu_deep_idle = B_FALSE;

		intr = intr_clear();
		while (!mutex_tryenter(&hpet_proxy_lock)) {
			/*
			 * spin
			 */
			intr_restore(intr);
			if (dead_count++ > hpet_spin_check) {
				dead_count = 0;
				if (gethrtime() > dead) {
					hpet_state.cpu_deep_idle = B_TRUE;
					mutex_exit(&hpet_state_lock);
					cmn_err(CE_NOTE,
					    "!hpet_deep_idle_config: deadman");
					return (B_FALSE);
				}
			}
			intr = intr_clear();
		}
		hpet_expire_all();
		mutex_exit(&hpet_proxy_lock);
		intr_restore(intr);

		hpet_disable_timer(&hpet_info, hpet_info.cstate_timer.timer);
		break;

	default:
		cmn_err(CE_NOTE, "!hpet_deep_idle_config: invalid code %d\n",
		    code);
		ret = B_FALSE;
		break;
	}
	mutex_exit(&hpet_state_lock);

	return (ret);
}

/*
 * Callback for _CST c-state change notifications.
 */
static void
hpet_cst_callback(uint32_t code)
{
	ulong_t		intr, dead_count = 0;
	hrtime_t	dead = gethrtime() + hpet_spin_timeout;

	switch (code) {
	case CST_EVENT_ONE_CSTATE:
		hpet_state.uni_cstate = B_TRUE;
		intr = intr_clear();
		while (!mutex_tryenter(&hpet_proxy_lock)) {
			/*
			 * spin
			 */
			intr_restore(intr);
			if (dead_count++ > hpet_spin_check) {
				dead_count = 0;
				if (gethrtime() > dead) {
					hpet_expire_all();
					cmn_err(CE_NOTE,
					    "!hpet_cst_callback: deadman");
					return;
				}
			}
			intr = intr_clear();
		}
		hpet_expire_all();
		mutex_exit(&hpet_proxy_lock);
		intr_restore(intr);
		break;

	case CST_EVENT_MULTIPLE_CSTATES:
		hpet_state.uni_cstate = B_FALSE;
		break;

	default:
		cmn_err(CE_NOTE, "!hpet_cst_callback: invalid code %d\n", code);
		break;
	}
}

/*
 * Interrupt Service Routine for HPET I/O-APIC-generated interrupts.
 * Used to wakeup CPUs from Deep C-state when their Local APIC Timer stops.
 * This ISR runs on one CPU which pokes other CPUs out of Deep C-state as
 * needed.
 */
/* ARGSUSED */
static uint_t
hpet_isr(char *arg)
{
	uint64_t	timer_status;
	uint64_t	timer_mask;
	ulong_t		intr, dead_count = 0;
	hrtime_t	dead = gethrtime() + hpet_isr_spin_timeout;

	timer_mask = HPET_INTR_STATUS_MASK(hpet_info.cstate_timer.timer);

	/*
	 * We are using a level-triggered interrupt.
	 * HPET sets timer's General Interrupt Status Register bit N.
	 * ISR checks this bit to see if it needs servicing.
	 * ISR then clears this bit by writing 1 to that bit.
	 */
	timer_status = hpet_read_gen_intrpt_stat(&hpet_info);
	if (!(timer_status & timer_mask))
		return (DDI_INTR_UNCLAIMED);
	hpet_write_gen_intrpt_stat(&hpet_info, timer_mask);

	/*
	 * Do not touch ISR data structures before checking the HPET's General
	 * Interrupt Status register.  The General Interrupt Status register
	 * will not be set by hardware until after timer interrupt generation
	 * is enabled by software.  Software allocates necessary data
	 * structures before enabling timer interrupts.  ASSERT the software
	 * data structures required to handle this interrupt are initialized.
	 */
	ASSERT(hpet_proxy_users != NULL);

	/*
	 * CPUs in deep c-states do not enable interrupts until after
	 * performing idle cleanup which includes descheduling themselves from
	 * the HPET.  The CPU running this ISR will NEVER find itself in the
	 * proxy list.  A lost wakeup may occur if this is false.
	 */
	ASSERT(hpet_proxy_users[CPU->cpu_id] == HPET_INFINITY);

	/*
	 * Higher level interrupts may deadlock with CPUs going idle if this
	 * ISR is prempted while holding hpet_proxy_lock.
	 */
	intr = intr_clear();
	while (!mutex_tryenter(&hpet_proxy_lock)) {
		/*
		 * spin
		 */
		intr_restore(intr);
		if (dead_count++ > hpet_spin_check) {
			dead_count = 0;
			if (gethrtime() > dead) {
				hpet_expire_all();
				return (DDI_INTR_CLAIMED);
			}
		}
		intr = intr_clear();
	}
	(void) hpet_guaranteed_schedule(HPET_INFINITY);
	mutex_exit(&hpet_proxy_lock);
	intr_restore(intr);

	return (DDI_INTR_CLAIMED);
}

/*
 * Used when disabling the HPET Timer interrupt.  CPUs in Deep C-state must be
 * woken up because they can no longer rely on the HPET's Timer to wake them.
 * We do not need to wait for CPUs to wakeup.
 */
static void
hpet_expire_all(void)
{
	processorid_t	id;

	for (id = 0; id < max_ncpus; ++id) {
		if (hpet_proxy_users[id] != HPET_INFINITY) {
			hpet_proxy_users[id] = HPET_INFINITY;
			if (id != CPU->cpu_id)
				poke_cpu(id);
		}
	}
}

/*
 * To avoid missed wakeups this function must guarantee either the HPET timer
 * was successfully programmed to the next expire time or there are no waiting
 * CPUs.
 *
 * Callers cannot enter C2 or deeper if the HPET could not be programmed to
 * generate its next interrupt to happen at required_wakeup_time or sooner.
 * Returns B_TRUE if the HPET was programmed to interrupt by
 * required_wakeup_time, B_FALSE if not.
 */
static boolean_t
hpet_guaranteed_schedule(hrtime_t required_wakeup_time)
{
	hrtime_t	now, next_proxy_time;
	processorid_t	id, next_proxy_id;
	int		proxy_timer = hpet_info.cstate_timer.timer;
	boolean_t	done = B_FALSE;

	ASSERT(mutex_owned(&hpet_proxy_lock));

	/*
	 * Loop until we successfully program the HPET,
	 * or no CPUs are scheduled to use the HPET as a proxy.
	 */
	do {
		/*
		 * Wake all CPUs that expired before now.
		 * Find the next CPU to wake up and next HPET program time.
		 */
		now = gethrtime();
		next_proxy_time = HPET_INFINITY;
		next_proxy_id = CPU->cpu_id;
		for (id = 0; id < max_ncpus; ++id) {
			if (hpet_proxy_users[id] < now) {
				hpet_proxy_users[id] = HPET_INFINITY;
				if (id != CPU->cpu_id)
					poke_cpu(id);
			} else if (hpet_proxy_users[id] < next_proxy_time) {
				next_proxy_time = hpet_proxy_users[id];
				next_proxy_id = id;
			}
		}

		if (next_proxy_time == HPET_INFINITY) {
			done = B_TRUE;
			/*
			 * There are currently no CPUs using the HPET's Timer
			 * as a proxy for their LAPIC Timer.  The HPET's Timer
			 * does not need to be programmed.
			 *
			 * Letting the HPET timer wrap around to the current
			 * time is the longest possible timeout.
			 * A 64-bit timer will wrap around in ~ 2^44 seconds.
			 * A 32-bit timer will wrap around in ~ 2^12 seconds.
			 *
			 * Disabling the HPET's timer interrupt requires a
			 * (relatively expensive) write to the HPET.
			 * Instead we do nothing.
			 *
			 * We are gambling some CPU will attempt to enter a
			 * deep c-state before the timer wraps around.
			 * We assume one spurious interrupt in a little over an
			 * hour has less performance impact than writing to the
			 * HPET's timer disable bit every time all CPUs wakeup
			 * from deep c-state.
			 */

		} else {
			/*
			 * Idle CPUs disable interrupts before programming the
			 * HPET to prevent a lost wakeup if the HPET
			 * interrupts the idle cpu before it can enter a
			 * Deep C-State.
			 */
			if (hpet_timer_program(&hpet_info, proxy_timer,
			    HRTIME_TO_HPET_TICKS(next_proxy_time - gethrtime()))
			    != AE_OK) {
				/*
				 * We could not program the HPET to wakeup the
				 * next CPU.  We must wake the CPU ourself to
				 * avoid a lost wakeup.
				 */
				hpet_proxy_users[next_proxy_id] = HPET_INFINITY;
				if (next_proxy_id != CPU->cpu_id)
					poke_cpu(next_proxy_id);
			} else {
				done = B_TRUE;
			}
		}

	} while (!done);

	return (next_proxy_time <= required_wakeup_time);
}

/*
 * Use an HPET timer to act as this CPU's proxy local APIC timer.
 * Used in deep c-states C2 and above while the CPU's local APIC timer stalls.
 * Called by the idle thread with interrupts enabled.
 * Always returns with interrupts disabled.
 *
 * There are 3 possible outcomes from this function:
 * 1. The Local APIC Timer was already disabled before this function was called.
 *	LAPIC TIMER	: disabled
 *	HPET		: not scheduled to wake this CPU
 *	*lapic_expire	: (hrtime_t)HPET_INFINITY
 *	Returns		: B_TRUE
 * 2. Successfully programmed the HPET to act as a LAPIC Timer proxy.
 *	LAPIC TIMER	: disabled
 *	HPET		: scheduled to wake this CPU
 *	*lapic_expire	: hrtime_t when LAPIC timer would have expired
 *	Returns		: B_TRUE
 * 3. Failed to programmed the HPET to act as a LAPIC Timer proxy.
 *	LAPIC TIMER	: enabled
 *	HPET		: not scheduled to wake this CPU
 *	*lapic_expire	: (hrtime_t)HPET_INFINITY
 *	Returns		: B_FALSE
 *
 * The idle thread cannot enter Deep C-State in case 3.
 * The idle thread must re-enable & re-program the LAPIC_TIMER in case 2.
 */
static boolean_t
hpet_use_hpet_timer(hrtime_t *lapic_expire)
{
	extern hrtime_t	apic_timer_stop_count(void);
	extern void	apic_timer_restart(hrtime_t);
	hrtime_t	now, expire, dead;
	uint64_t	lapic_count, dead_count;
	cpupart_t	*cpu_part;
	processorid_t	cpu_sid;
	processorid_t	cpu_id = CPU->cpu_id;
	processorid_t	id;
	boolean_t	rslt;
	boolean_t	hset_update;

	cpu_part = CPU->cpu_part;
	cpu_sid = CPU->cpu_seqid;

	ASSERT(CPU->cpu_thread == CPU->cpu_idle_thread);

	/*
	 * A critical section exists between when the HPET is programmed
	 * to interrupt the CPU and when this CPU enters an idle state.
	 * Interrupts must be blocked during that time to prevent lost
	 * CBE wakeup interrupts from either LAPIC or HPET.
	 *
	 * Must block interrupts before acquiring hpet_proxy_lock to prevent
	 * a deadlock with the ISR if the ISR runs on this CPU after the
	 * idle thread acquires the mutex but before it clears interrupts.
	 */
	ASSERT(!interrupts_enabled());
	lapic_count = apic_timer_stop_count();
	now = gethrtime();
	dead = now + hpet_idle_spin_timeout;
	*lapic_expire = expire = now + lapic_count;
	if (lapic_count == (hrtime_t)-1) {
		/*
		 * LAPIC timer is currently disabled.
		 * Will not use the HPET as a LAPIC Timer proxy.
		 */
		*lapic_expire = (hrtime_t)HPET_INFINITY;
		return (B_TRUE);
	}

	/*
	 * Serialize hpet_proxy data structure manipulation.
	 */
	dead_count = 0;
	while (!mutex_tryenter(&hpet_proxy_lock)) {
		/*
		 * spin
		 */
		apic_timer_restart(expire);
		sti();
		cli();

		if (dead_count++ > hpet_spin_check) {
			dead_count = 0;
			hset_update = (((CPU->cpu_flags & CPU_OFFLINE) == 0) &&
			    (ncpus > 1));
			if (hset_update &&
			    !bitset_in_set(&cpu_part->cp_haltset, cpu_sid)) {
				*lapic_expire = (hrtime_t)HPET_INFINITY;
				return (B_FALSE);
			}
		}

		lapic_count = apic_timer_stop_count();
		now = gethrtime();
		*lapic_expire = expire = now + lapic_count;
		if (lapic_count == (hrtime_t)-1) {
			/*
			 * LAPIC timer is currently disabled.
			 * Will not use the HPET as a LAPIC Timer proxy.
			 */
			*lapic_expire = (hrtime_t)HPET_INFINITY;
			return (B_TRUE);
		}
		if (now > dead) {
			apic_timer_restart(expire);
			*lapic_expire = (hrtime_t)HPET_INFINITY;
			return (B_FALSE);
		}
	}

	if ((hpet_state.cpr == B_TRUE) ||
	    (hpet_state.cpu_deep_idle == B_FALSE) ||
	    (hpet_state.proxy_installed == B_FALSE) ||
	    (hpet_state.uni_cstate == B_TRUE)) {
		mutex_exit(&hpet_proxy_lock);
		apic_timer_restart(expire);
		*lapic_expire = (hrtime_t)HPET_INFINITY;
		return (B_FALSE);
	}

	hpet_proxy_users[cpu_id] = expire;

	/*
	 * We are done if another cpu is scheduled on the HPET with an
	 * expire time before us.  The next HPET interrupt has been programmed
	 * to fire before our expire time.
	 */
	for (id = 0; id < max_ncpus; ++id) {
		if ((hpet_proxy_users[id] <= expire) && (id != cpu_id)) {
			mutex_exit(&hpet_proxy_lock);
			return (B_TRUE);
		}
	}

	/*
	 * We are the next lAPIC to expire.
	 * Program the HPET with our expire time.
	 */
	rslt = hpet_guaranteed_schedule(expire);
	mutex_exit(&hpet_proxy_lock);

	if (rslt == B_FALSE) {
		apic_timer_restart(expire);
		*lapic_expire = (hrtime_t)HPET_INFINITY;
	}

	return (rslt);
}

/*
 * Called by the idle thread when waking up from Deep C-state before enabling
 * interrupts.  With an array data structure it is faster to always remove
 * ourself from the array without checking if the HPET ISR already removed.
 *
 * We use a lazy algorithm for removing CPUs from the HPET's schedule.
 * We do not reprogram the HPET here because this CPU has real work to do.
 * On a idle system the CPU was probably woken up by the HPET's ISR.
 * On a heavily loaded system CPUs are not going into Deep C-state.
 * On a moderately loaded system another CPU will usually enter Deep C-state
 * and reprogram the HPET before the HPET fires with our wakeup.
 */
static void
hpet_use_lapic_timer(hrtime_t expire)
{
	extern void	apic_timer_restart(hrtime_t);
	processorid_t	cpu_id = CPU->cpu_id;

	ASSERT(CPU->cpu_thread == CPU->cpu_idle_thread);
	ASSERT(!interrupts_enabled());

	hpet_proxy_users[cpu_id] = HPET_INFINITY;

	/*
	 * Do not enable a LAPIC Timer that was initially disabled.
	 */
	if (expire != HPET_INFINITY)
		apic_timer_restart(expire);
}

/*
 * Initialize data structure to keep track of CPUs using HPET as a proxy for
 * their stalled local APIC timer.  For now this is just an array.
 */
static void
hpet_init_proxy_data(void)
{
	processorid_t	id;

	/*
	 * Use max_ncpus for hot plug compliance.
	 */
	hpet_proxy_users = kmem_zalloc(max_ncpus * sizeof (*hpet_proxy_users),
	    KM_SLEEP);

	/*
	 * Unused entries always contain HPET_INFINITY.
	 */
	for (id = 0; id < max_ncpus; ++id)
		hpet_proxy_users[id] = HPET_INFINITY;
}
