/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _VMM_DATA_H_
#define	_VMM_DATA_H_

/* VMM Data Classes */
#define	VDC_VERSION	1	/* Version information for each data class */

/* Classes bearing per-CPU data */
#define	VDC_REGISTER	2	/* Registers (GPR, segment, etc) */
#define	VDC_MSR		3	/* Model-specific registers */
#define	VDC_FPU		4	/* FPU (and associated SIMD) */
#define	VDC_LAPIC	5	/* Local APIC */
#define	VDC_VMM_ARCH	6	/* Arch-specific VMM state (VMX/SVM) */

/* Classes for system-wide devices */
#define	VDC_IOAPIC	7	/* bhyve IO-APIC */
#define	VDC_ATPIT	8	/* i8254 PIT */
#define	VDC_ATPIC	9	/* i8259 PIC */
#define	VDC_HPET	10	/* HPET */
#define	VDC_PM_TIMER	11	/* ACPI Power Management Timer */
#define	VDC_RTC		12	/* IBM PC Real Time Clock */

#define	VDC_VMM_TIME	13	/* Time-related VMM data */

/* Indicates top of VMM Data Class range, updated as classes are added */
#define	VDC_MAX		(VDC_VMM_TIME + 1)


/* VMM Data Identifiers */

/*
 * Generic field encoding for 64-bit (or smaller) data which are identified by a
 * 32-bit (or smaller) name.
 *
 * Used by the following classes/version:
 * - VDC_REGISTER v1: `vm_reg_name` identifiers
 * - VDC_MSR v1: MSR identifiers
 * - VDC_VMM_ARCH v1: Identifiers described below
 */
struct vdi_field_entry_v1 {
	uint32_t	vfe_ident;
	uint32_t	_pad;
	uint64_t	vfe_value;
};

/* VDC_VERSION */
struct vdi_version_entry_v1 {
	uint16_t	vve_class;
	uint16_t	vve_version;
	uint16_t	vve_len_expect;
	uint16_t	vve_len_per_item;
};

/*
 * VDC_FPU:
 *
 * Unimplemented for now.  Use VM_GET_FPU/VM_SET_FPU ioctls.
 */

/* VDC_LAPIC: */

struct vdi_lapic_page_v1 {
	uint32_t	vlp_id;
	uint32_t	vlp_version;
	uint32_t	vlp_tpr;
	uint32_t	vlp_apr;
	uint32_t	vlp_ldr;
	uint32_t	vlp_dfr;
	uint32_t	vlp_svr;
	uint32_t	vlp_isr[8];
	uint32_t	vlp_tmr[8];
	uint32_t	vlp_irr[8];
	uint32_t	vlp_esr;
	uint32_t	vlp_lvt_cmci;
	uint64_t	vlp_icr;
	uint32_t	vlp_lvt_timer;
	uint32_t	vlp_lvt_thermal;
	uint32_t	vlp_lvt_pcint;
	uint32_t	vlp_lvt_lint0;
	uint32_t	vlp_lvt_lint1;
	uint32_t	vlp_lvt_error;
	uint32_t	vlp_icr_timer;
	uint32_t	vlp_dcr_timer;
};

struct vdi_lapic_v1 {
	struct vdi_lapic_page_v1 vl_lapic;
	uint64_t		vl_msr_apicbase;
	int64_t			vl_timer_target;
	uint32_t		vl_esr_pending;
};

/*
 * VDC_VMM_ARCH:
 */

/*
 * Version 1 identifiers:
 */

/*
 * VM-wide:
 */

/* Is the VM currently in the "paused" state? (0 or 1) */
#define	VAI_VM_IS_PAUSED	4

/*
 * per-vCPU:
 *
 * Note: While these are currently defined with values disjoint from those in
 * the VM-wide category, it is not required that they be.  The VM-wide and
 * per-vCPU identifiers are distinguished by vm_data_xfer`vdx_vcpuid.
 */

/* NMI pending injection for vCPU (0 or 1) */
#define	VAI_PEND_NMI		10
/* extint pending injection for vCPU (0 or 1) */
#define	VAI_PEND_EXTINT		11
/* HW exception pending injection for vCPU */
#define	VAI_PEND_EXCP		12
/* exception/interrupt pending injection for vCPU */
#define	VAI_PEND_INTINFO	13

/* VDC_IOAPIC: */

struct vdi_ioapic_v1 {
	uint64_t	vi_pin_reg[32];
	uint32_t	vi_pin_level[32];
	uint32_t	vi_id;
	uint32_t	vi_reg_sel;
};

/* VDC_ATPIT: */

struct vdi_atpit_channel_v1 {
	uint16_t	vac_initial;
	uint16_t	vac_reg_cr;
	uint16_t	vac_reg_ol;
	uint8_t		vac_reg_status;
	uint8_t		vac_mode;
	/*
	 * vac_status bits:
	 * - 0b00001 status latched
	 * - 0b00010 output latched
	 * - 0b00100 control register sel
	 * - 0b01000 output latch sel
	 * - 0b10000 free-running timer
	 */
	uint8_t		vac_status;

	int64_t		vac_time_target;
};

struct vdi_atpit_v1 {
	struct vdi_atpit_channel_v1 va_channel[3];
};

/* VDC_ATPIC: */

struct vdi_atpic_chip_v1 {
	uint8_t		vac_icw_state;
	/*
	 * vac_status bits:
	 * - 0b00000001 ready
	 * - 0b00000010 auto EOI
	 * - 0b00000100 poll
	 * - 0b00001000 rotate
	 * - 0b00010000 special full nested
	 * - 0b00100000 read isr next
	 * - 0b01000000 intr raised
	 * - 0b10000000 special mask mode
	 */
	uint8_t		vac_status;
	uint8_t		vac_reg_irr;
	uint8_t		vac_reg_isr;
	uint8_t		vac_reg_imr;
	uint8_t		vac_irq_base;
	uint8_t		vac_lowprio;
	uint8_t		vac_elc;
	uint32_t	vac_level[8];
};

struct vdi_atpic_v1 {
	struct vdi_atpic_chip_v1 va_chip[2];
};

/* VDC_HPET: */

struct vdi_hpet_timer_v1 {
	uint64_t	vht_config;
	uint64_t	vht_msi;
	uint32_t	vht_comp_val;
	uint32_t	vht_comp_rate;
	int64_t		vht_time_target;
};

struct vdi_hpet_v1 {
	uint64_t	vh_config;
	uint64_t	vh_isr;
	uint32_t	vh_count_base;
	int64_t		vh_time_base;

	struct vdi_hpet_timer_v1	vh_timers[8];
};

/* VDC_PM_TIMER: */

struct vdi_pm_timer_v1 {
	int64_t		vpt_time_base;
	/*
	 * Since the PM-timer IO port registration can be set by a dedicated
	 * ioctl today, it is considered a read-only field in the vmm data
	 * interface and its contents will be ignored when writing state data to
	 * the timer.
	 */
	uint16_t	vpt_ioport;
};

/* VDC_RTC: */

struct vdi_rtc_v1 {
	uint8_t		vr_content[128];
	uint8_t		vr_addr;
	int64_t		vr_time_base;
	uint64_t	vr_rtc_sec;
	uint64_t	vr_rtc_nsec;
};

/* VDC_VMM_TIME: */

/*
 * Interface for modifying time-related data of a guest, allowing the guest's
 * TSC and device timers to continue working across inter-machine live
 * migrations.
 *
 * Reads of this data will populate all fields, including:
 * - current guest TSC (a calculated value)
 * - guest TSC frequency
 * - guest boot_time, which tracks the offset of the guest boot based on host
 *   hrtime
 * - current host hrtime and wall clock time (hrestime) at the time of read
 *
 * Callers writing this data may want to make adjustments to the guest TSC based
 * on the time between read and write, such as in the case of a migration.
 * For migrations between machines, the boot_hrtime must also be updated based
 * on the hrtime of the target system. Callers should populate the host time
 * fields for the host the write is performed on. These fields are used by the
 * write interface to make additional adjustments to the guest fields to account
 * for latency between the userspace adjustment and kernel receipt of those
 * values.
 */
struct vdi_time_info_v1 {
	/* guest-related fields */
	uint64_t	vt_guest_freq;	/* guest TSC frequency (hz) */
	uint64_t	vt_guest_tsc;	/* current guest TSC */
	int64_t		vt_boot_hrtime; /* guest boot_hrtime */

	/* host time fields */
	int64_t		vt_hrtime;	/* host hrtime (ns) */
	uint64_t	vt_hres_sec;	/* host hrestime (sec) */
	uint64_t	vt_hres_ns;	/* host hrestime (ns) */
};

#endif /* _VMM_DATA_H_ */
