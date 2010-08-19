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

#ifndef	_HPET_ACPI_H
#define	_HPET_ACPI_H

#if defined(_KERNEL)
#include <sys/acpi/acpi.h>
#include <sys/acpi/actbl1.h>
#include <sys/acpica.h>
#endif	/* defined(_KERNEL) */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Solaris uses an HPET Timer to generate interrupts for CPUs in Deep C-state
 * with stalled LAPIC Timers.  All CPUs use one HPET timer.  The timer's
 * interrupt targets one CPU (via the I/O APIC).  The one CPU that receives
 * the HPET's interrupt wakes up other CPUs as needed during the HPET Interrupt
 * Service Routing.  The HPET ISR uses poke_cpus to wake up other CPUs with an
 * Inter Processor Interrupt.
 *
 * Please see the Intel Programmer's guides.  Interrupts are disabled before
 * a CPU Halts into Deep C-state.  (This allows CPU-hardware-specific cleanup
 * before servicing interrupts.)  When a Deep C-state CPU wakes up (due to
 * an externally generated interrupt), it resume execution where it halted.
 * The CPU returning from Deep C-state must enable interrupts before it will
 * handle the pending interrupt that woke it from Deep C-state.
 *
 *
 * HPET bits as defined in the Intel IA-PC HPET Specification Rev 1.0a.
 *
 * The physical address space layout of the memory mapped HPET looks like this:
 *
 * struct hpet {
 *	uint64_t	gen_cap;
 *	uint64_t	res1;
 *	uint64_t	gen_config;
 *	uint64_t	res2;
 *	uint64_t	gen_inter_stat;
 *	uint64_t	res3;
 *	uint64_t	main_counter_value;
 *	uint64_t	res4;
 *	stuct hpet_timer {
 *		uint64_t	config_and_capability;
 *		uint64_t	comparator_value;
 *		uint64_t	FSB_interrupt_route;
 *		uint64_t	reserved;
 *	} timers[32];
 * }
 *
 * There are 32 possible timers in an hpet.  Only the first 3 timers are
 * required.  The other 29 timers are optional.
 *
 * HPETs can have 64-bit or 32-bit timers.  Timers/compare registers can
 * be 64-bit or 32-bit and can be a mixture of both.
 * The first two timers are not used.  The HPET spec intends the first two
 * timers to be used as "legacy replacement" for the PIT and RTC timers.
 *
 * Solaris uses the first available non-legacy replacement timer as a proxy
 * timer for processor Local APIC Timers that stop in deep idle C-states.
 */

/*
 * We only use HPET table 1 on x86.  Typical x86 systems only have 1 HPET.
 * ACPI allows for multiple HPET tables to describe multiple HPETs.
 */
#define	HPET_TABLE_1		(1)

/*
 * HPET Specification 1.0a defines the HPET to occupy 1024 bytes regardless of
 * the number of counters (3 to 32) in this implementation.
 */
#define	HPET_SIZE		(1024)

/*
 * Offsets of hpet registers and macros to access them from HPET base address.
 */
#define	HPET_GEN_CAP_OFFSET		(0)
#define	HPET_GEN_CONFIG_OFFSET		(0x10)
#define	HPET_GEN_INTR_STAT_OFFSET	(0x20)
#define	HPET_MAIN_COUNTER_OFFSET	(0xF0)
#define	HPET_TIMER_N_CONF_OFFSET(n)	(0x100 + (n * 0x20))
#define	HPET_TIMER_N_COMP_OFFSET(n)	(0x108 + (n * 0x20))

#define	OFFSET_ADDR(a, o)		(((uintptr_t)(a)) + (o))
#define	HPET_GEN_CAP_ADDRESS(la)				\
		    OFFSET_ADDR(la, HPET_GEN_CAP_OFFSET)
#define	HPET_GEN_CONFIG_ADDRESS(la)				\
		    OFFSET_ADDR(la, HPET_GEN_CONFIG_OFFSET)
#define	HPET_GEN_INTR_STAT_ADDRESS(la)				\
		    OFFSET_ADDR(la, HPET_GEN_INTR_STAT_OFFSET)
#define	HPET_MAIN_COUNTER_ADDRESS(la)				\
		    OFFSET_ADDR(la, HPET_MAIN_COUNTER_OFFSET)
#define	HPET_TIMER_N_CONF_ADDRESS(la, n)			\
		    OFFSET_ADDR(la, HPET_TIMER_N_CONF_OFFSET(n))
#define	HPET_TIMER_N_COMP_ADDRESS(la, n)			\
		    OFFSET_ADDR(la, HPET_TIMER_N_COMP_OFFSET(n))

/*
 * HPET General Capabilities and ID Register
 */
typedef struct hpet_gen_cap {
	uint32_t	counter_clk_period;	/* period in femtoseconds */
	uint32_t	vendor_id	:16;	/* vendor */
	uint32_t	leg_route_cap	:1;	/* 1=LegacyReplacemnt support */
	uint32_t	res1		:1;	/* reserved */
	uint32_t	count_size_cap	:1;	/* 0=32bit, 1=64bit wide */
	uint32_t	num_tim_cap	:5;	/* number of timers -1 */
	uint32_t	rev_id		:8;	/* revision number */
} hpet_gen_cap_t;

/*
 * Macros to parse fields of the hpet General Capabilities and ID Register.
 */
#define	HPET_GCAP_CNTR_CLK_PERIOD(l)	(l >> 32)
#define	HPET_GCAP_VENDOR_ID(l)		BITX(l, 31, 16)
#define	HPET_GCAP_LEG_ROUTE_CAP(l)	BITX(l, 15, 15)
#define	HPET_GCAP_CNT_SIZE_CAP(l)	BITX(l, 13, 13)
#define	HPET_GCAP_NUM_TIM_CAP(l)	BITX(l, 12, 8)
#define	HPET_GCAP_REV_ID(l)		BITX(l, 7, 0)

/*
 * From HPET spec "The value in this field must be less than or equal to":
 */
#define	HPET_MAX_CLK_PERIOD	(0x5F5E100)

/*
 * Femto seconds in a second.
 */
#if defined(__i386)
#define	HPET_FEMTO_TO_NANO	(1000000LL)
#define	HRTIME_TO_HPET_TICKS(t)	(((t) * HPET_FEMTO_TO_NANO) / hpet_info.period)
#else
#define	HPET_FEMTO_TO_NANO	(1000000L)
#define	HRTIME_TO_HPET_TICKS(t)	(((t) * HPET_FEMTO_TO_NANO) / hpet_info.period)
#endif	/* (__i386) */

/*
 * HPET General Configuration Register
 */
typedef struct hpet_gen_config_bitfield {
	uint32_t	leg_rt_cnf :1;		/* legacy replacement route */
	uint32_t	enable_cnf :1;		/* overal enable */
} hpet_gen_conf_t;

/*
 * General Configuration Register fields.
 */
#define	HPET_GCFR_LEG_RT_CNF		(0x2)		/* bit field value */
#define	HPET_GCFR_ENABLE_CNF		(0x1)		/* bit field value */
#define	HPET_GCFR_LEG_RT_CNF_BITX(l)	BITX(l, 1, 1)
#define	HPET_GCFR_ENABLE_CNF_BITX(l)	BITX(l, 0, 0)

/*
 * General Interrupt Status Register.
 */
#define	HPET_GIS_T2_INT_STS(l)		BITX(l, 2, 2)
#define	HPET_GIS_T1_INT_STS(l)		BITX(l, 1, 1)
#define	HPET_GIS_T0_INT_STS(l)		BITX(l, 0, 0)
#define	HPET_GIS_TN_INT_STS(l, n)	BITX(l, n, n)

#define	HPET_INTR_STATUS_MASK(timer)	((uint64_t)1 << (timer))

/*
 * HPET Timer N Configuration and Capabilities Register
 */
typedef struct hpet_TN_conf_cap {
	uint32_t	int_route_cap;		/* available I/O APIC intrups */
	uint32_t	res1		:16;	/* reserved */
	uint32_t	fsb_int_del_cap	:1;	/* FSB interrupt supported */
	uint32_t	fsb_int_en_cnf	:1;	/* Set FSB intr delivery */
	uint32_t	int_route_cnf	:5;	/* I/O APIC interrupt to use */
	uint32_t	mode32_cnf	:1;	/* Force 32-bit mode */
	uint32_t	res2		:1;	/* reserved */
	uint32_t	val_set_cnf	:1;	/* Set periodic mode accumula */
	uint32_t	size_cap	:1;	/* 1=64bit, 0=32bit timer */
	uint32_t	per_int_cap	:1;	/* 1=periodic mode supported */
	uint32_t	type_cnf	:1;	/* Enable periodic mode */
	uint32_t	int_enb_cnf	:1;	/* Enable interrupt generat */
	uint32_t	int_type_cnf	:1;	/* 0=edge, 1=level triggered */
	uint32_t	res3		:1;	/* reserved */
} hpet_TN_conf_cap_t;

/*
 * There are 3 to 32 timers on each HPET.
 */
#define	HPET_TIMER_N_INT_ROUTE_CAP(l)	(l >> 32)
#define	HPET_TIMER_N_INT_TYPE_CNF(l)	BITX(l, 1, 1)
#define	HPET_TIMER_N_INT_ENB_CNF(l)	BITX(l, 2, 2)
#define	HPET_TIMER_N_TYPE_CNF(l)	BITX(l, 3, 3)
#define	HPET_TIMER_N_PER_INT_CAP(l)	BITX(l, 4, 4)
#define	HPET_TIMER_N_SIZE_CAP(l)	BITX(l, 5, 5)
#define	HPET_TIMER_N_VAL_SET_CNF(l)	BITX(l, 6, 6)
#define	HPET_TIMER_N_MODE32_CNF(l)	BITX(l, 8, 8)
#define	HPET_TIMER_N_INT_ROUTE_CNF(l)	BITX(l, 13, 9)
#define	HPET_TIMER_N_FSB_EN_CNF(l)	BITX(l, 14, 14)
#define	HPET_TIMER_N_FSB_INT_DEL_CAP(l)	BITX(l, 15, 15)

#define	HPET_TIMER_N_INT_TYPE_CNF_BIT	(1 << 1)
#define	HPET_TIMER_N_INT_ENB_CNF_BIT	(1 << 2)
#define	HPET_TIMER_N_TYPE_CNF_BIT	(1 << 3)
#define	HPET_TIMER_N_FSB_EN_CNF_BIT	(1 << 14)
#define	HPET_TIMER_N_INT_ROUTE_SHIFT(i)	(i << 9)

/*
 * HPET Spec reserves timers 0 and 1 for legacy timer replacement (PIT and RTC).
 * Available timers for other use such as LACPI proxy during Deep C-State
 * start at timer 2.
 */
#define	HPET_FIRST_NON_LEGACY_TIMER	(2)

/*
 * HPET timer and interrupt used as LAPIC proxy during deep C-State.
 */
typedef struct cstate_timer {
	int	timer;
	int	intr;
} cstate_timer_t;

/*
 * Data structure of useful HPET device information.
 */
typedef struct hpet_info {
	hpet_gen_cap_t	gen_cap;
	hpet_gen_conf_t	gen_config;
	uint64_t	gen_intrpt_stat;
	uint64_t	main_counter_value;
	void		*logical_address;	/* HPET VA memory map */
	hpet_TN_conf_cap_t *timer_n_config;	/* N Timer config and cap */
	uint32_t	num_timers;		/* number of timers */
	uint32_t	allocated_timers;	/* bitmap of timers in use */
	cstate_timer_t	cstate_timer;	/* HPET Timer used for LAPIC proxy */
	uint64_t	hpet_main_counter_reads[2];
	hrtime_t	tsc[3];
	hrtime_t	period;		/* counter_clk_period in Femto Secs */
} hpet_info_t;

#if defined(_KERNEL)

/*
 * Spin mutexes are used in several places because idle threads cannot block.
 * These defines provide a mechanism to break out of spin loops to prevent
 * system hangs if a CPU can never get the lock (due to an unknown
 * hardware/software bug).  100 microsecond was chosen after extensive stress
 * testing.
 */
#define	HPET_SPIN_CHECK		(1000)
#define	HPET_SPIN_TIMEOUT	(100000)

/*
 * There is one of these per CPU using the HPET as a proxy for its stalled
 * local APIC while in c-state >= C2.
 */
typedef hrtime_t hpet_proxy_t;

extern ACPI_TABLE_HPET	*hpet_table;
extern hpet_info_t	hpet_info;

#endif	/* defined(_KERNEL) */

#ifdef __cplusplus
}
#endif

#endif	/* _HPET_ACPI_H */
